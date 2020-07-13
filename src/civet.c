#include <string.h>
#include <flecs_systems_civetweb.h>
#include "civetweb.h"

#define INIT_REQUEST_COUNT (8)

/* Server data allocated on heap (not in ECS). This ensures the pointer is
 * stable and cannot change due to data moving around. */
typedef struct CivetServerData {
    struct mg_context *server;

    /* Port number of server */
    int16_t port;

    /* Cache endpoints defined in ECS, so we won't need to access the ECS system
     * when receiving a request, which would not be thread safe as civetweb does
     * not provide the option to manually control threading. */
    ecs_vector_t *endpoints;
    ecs_vector_t *endpoint_entities;

    /* Number of requests waiting */
    int requests_waiting;

    /* Access to ECS world */
    ecs_world_t *world;
} CivetServerData;

/* ECS server component only contains a pointer to the heap structure */
typedef struct EcsCivetServer {
    CivetServerData *server_data;
} EcsCivetServer;

typedef struct EndpointEvalCtx {
    EcsHttpRequest request;
    CivetServerData *server_data;
} EndpointEvalCtx;

static
EcsHttpMethod method_from_str(
    const char *method)
{
    if (!strcmp(method, "GET")) return EcsHttpGet;
    else if (!strcmp(method, "POST")) return EcsHttpPost;
    else if (!strcmp(method, "PUT")) return EcsHttpPut;
    else if (!strcmp(method, "DELETE")) return EcsHttpDelete;
    else return EcsHttpMethodUnknown;
}

static
int CbLogMessage(
    const struct mg_connection *conn,
    const char *msg)
{
    printf("civetweb: %s\n", (char*)msg);
    return 1;
}

static
int CbWsConnect(
    const struct mg_connection *conn,
    void *cbdata)
{
    return 1;
}

static
void CbWsReady(
    struct mg_connection *conn,
    void *cbdata)
{
}

static
int CbWsData(
    struct mg_connection *conn,
    int bits,
    char *data,
    size_t len,
    void *cbdata)
{
    return 1;
}

static
void CbWsClose(
    const struct mg_connection *conn,
    void *cbdata)
{
}

static
void do_reply(
    struct mg_connection *conn,
    uint16_t status,
    char *header,
    char *body)
{
    ecs_strbuf_t buf = ECS_STRBUF_INIT;
    ecs_strbuf_append(&buf, "HTTP/1.1 %d OK\r\nAccess-Control-Allow-Origin: *\r\n", status);
    if (header) {
        ecs_strbuf_appendstr_zerocpy(&buf, header);
    }
    ecs_strbuf_appendstr(&buf, "\r\n");
    if (body) ecs_strbuf_appendstr_zerocpy(&buf, body);
    char *msg = ecs_strbuf_get(&buf);
    mg_write(conn, msg, strlen(msg));
    free(msg);
}

static
bool eval_endpoints(EndpointEvalCtx *ctx) {
    EcsHttpReply reply = {.status = 200};
    EcsHttpRequest *request = &ctx->request;
    CivetServerData *server_data = ctx->server_data;
    struct mg_connection *conn = request->ctx;
    const char *r_url = request->url;
    bool handled = false;
    if (r_url[0] == '/') r_url ++;

    EcsHttpEndpoint *buffer = ecs_vector_first(server_data->endpoints, EcsHttpEndpoint);
    ecs_entity_t *entity_buffer = ecs_vector_first(server_data->endpoint_entities, ecs_entity_t);
    uint32_t i, count = ecs_vector_count(server_data->endpoints);

    for (i = 0; i < count; i ++) {
        EcsHttpEndpoint *endpoint = &buffer[i];
        char *e_url = endpoint->url;
        if (e_url[0] == '/') e_url ++;
        uint32_t e_url_len = strlen(e_url);

        if (!strncmp(e_url, r_url, e_url_len)) {
            const char *orig_r_url = r_url;
            r_url = r_url + e_url_len;

            if (!r_url[0] || r_url[0] == '/' || r_url == orig_r_url) {
                ecs_entity_t entity = entity_buffer[i];
                ecs_world_t *world = server_data->world;
                if (r_url[0]) {
                    if (r_url != orig_r_url) {
                        request->relative_url = r_url + 1;
                    } else {
                        request->relative_url = r_url;
                    }
                } else {
                    request->relative_url = "";
                }

                ecs_trace_2("civet: 201: endpoint '/%s' matched", e_url);

                handled = endpoint->action(world, entity, endpoint, request, &reply);

                if (handled) {
                    if (reply.is_file) {
                        mg_send_file(conn, reply.body);
                    } else {
                        do_reply(conn, reply.status, reply.header, reply.body);
                    }
                    break;
                }
            } else {
                continue;
            }
        }
    }

    return handled;
}

static
int CbOnRequest(
    struct mg_connection *conn,
    void *cbdata)
{
    const struct mg_request_info *req_info = mg_get_request_info(conn);
    EcsHttpMethod method = method_from_str(req_info->request_method);
    CivetServerData *server_data = cbdata;

    EndpointEvalCtx eval_ctx = {
        .request = {
            .method = method,
            .url = req_info->local_uri,
            .params = req_info->query_string,
            .ctx = conn
        },
        .server_data = server_data
    };

    ecs_trace_2("civet: %s: uri=%s query=%s", 
        req_info->request_method, req_info->local_uri, req_info->query_string);

    /* Evaluate request for all endpoints for this server */
    ecs_begin_wait(server_data->world);
    ecs_lock(server_data->world);
    ecs_end_wait(server_data->world);

    bool handled = eval_endpoints(&eval_ctx);
    ecs_unlock(server_data->world);

    if (!handled) {
        do_reply(conn, 404, NULL, NULL);
        ecs_trace_2("civet: 404: no endpoint found");
    }

    return 1;
}

static
void CivetDeinit(ecs_iter_t *it) {
    EcsCivetServer *c = ecs_column(it, EcsCivetServer, 1);

    int i;
    for (i = 0; i < it->count; i ++) {
        CivetServerData *data = c[i].server_data;
        mg_stop(data->server);
        ecs_os_free(data);
    }
}

static
void CivetSet(ecs_iter_t *it) {
    ecs_world_t *world = it->world;

    EcsHttpServer *server = ecs_column(it, EcsHttpServer, 1);
    EcsCivetServer *civet_server = ecs_column(it, EcsCivetServer, 2);
    ecs_entity_t ecs_entity(EcsCivetServer) = ecs_column_entity(it, 2);

    int i;
    for (i = 0; i < it->count; i ++) {
        /* If this server already exists, check if it uses the same port. If not
         * it must be recreated. */
        if (civet_server) {
            CivetServerData *data = civet_server[i].server_data;
            if (data->port == server[i].port) {
                /* Ports are the same, no changes needed */
                continue;
            } else {
                /* Ports are not the same, need to recreate server */
                mg_stop(data->server);
                ecs_os_free(data);
            }
        }

        char port[15];
        sprintf(port, "%u", server[i].port);

        const char *options[] = {
            "document_root", ".",
            "listening_ports", port,
            "request_timeout_ms", "10000",
            "error_log_file", "error.log",
            "enable_auth_domain_check", "no",
#if defined(__linux__)
            "allow_sendfile_call", "true",
#endif
             NULL};

        if (!mg_check_feature(8)) {
            /* IPv6 not supported */
        }

        if (!mg_check_feature(16)) {
            /* Websockets not supported */
        }

        if (!mg_check_feature(2)) {
            /* SSL not supported */
        }

        /* Start CivetWeb web server */
        struct mg_callbacks callbacks;
        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.log_message = CbLogMessage;

        /* Add server object to entity */
        CivetServerData *server_data = ecs_os_malloc(sizeof(CivetServerData));
        ecs_assert(server_data != NULL, ECS_OUT_OF_MEMORY, NULL);

        ecs_trace_1("civet: starting server on port %u", server[i].port);

        server_data->world = world;
        server_data->server = mg_start(&callbacks, server_data, options);
        server_data->endpoints = ecs_vector_new(EcsHttpEndpoint, 0);
        server_data->endpoint_entities = ecs_vector_new(ecs_entity_t, 0);
        server_data->requests_waiting = 0;
        server_data->port = server[i].port;

        /* Add component with Civetweb data */
        ecs_set(world, it->entities[i], EcsCivetServer, {
            .server_data = server_data
        });

        /* Set handler for requests */
        mg_set_request_handler(server_data->server, "**", CbOnRequest, server_data);

        /* Set websocket handlers */
        mg_set_websocket_handler(
            server_data->server, "/", CbWsConnect, CbWsReady, CbWsData, 
            CbWsClose, server_data);
    }
}

static
void CivetUnset(ecs_iter_t *it) {
    EcsCivetServer *civet_server = ecs_column(it, EcsCivetServer, 1);

    int32_t i;
    for (i = 0; i < it->count; i ++) {
        CivetServerData *data = civet_server[i].server_data;
        mg_stop(data->server);
        ecs_vector_free(data->endpoints);
        ecs_vector_free(data->endpoint_entities);
        ecs_os_free(data);
    }
}

static
ecs_entity_t find_server(
    ecs_world_t *world,
    ecs_entity_t ep,
    ecs_entity_t server)
{
    ecs_type_t type = ecs_get_type(world, ep);
    ecs_entity_t *array = ecs_vector_first(type, ecs_entity_t);
    uint32_t i, count = ecs_vector_count(type);
 
    for (i = 0; i < count; i ++) {
        ecs_entity_t e = array[i];
        if (e & ECS_CHILDOF) {
            if (ecs_has_entity(world, e & ECS_ENTITY_MASK, server)) {
                return e & ECS_ENTITY_MASK;
            }
        }
    }

    return 0;
}

static
void CivetRegisterEndpoint(ecs_iter_t *it) {
    EcsHttpEndpoint *ep = ecs_column(it, EcsHttpEndpoint, 1);
    ecs_entity_t server_component_handle = ecs_column_entity(it, 2);

    int i;
    for (i = 0; i < it->count; i ++) {
        ecs_entity_t entity = it->entities[i];

        ecs_entity_t server = find_server(it->world, entity, server_component_handle);
        if (server) {
            const EcsCivetServer *c = ecs_get_w_entity(
                it->world, server, server_component_handle);

            CivetServerData *data = c->server_data;

            EcsHttpEndpoint *new_ep = ecs_vector_add(&data->endpoints, EcsHttpEndpoint);
            *new_ep = ep[i];
            ecs_entity_t *new_entity = ecs_vector_add(&data->endpoint_entities, ecs_entity_t);
            *new_entity = entity;
        } else {
            ecs_os_warn("no server found for endpoint '%s'", ep->url);
        }
    }
}

void FlecsSystemsCivetwebImport(
    ecs_world_t *world)
{
    ECS_IMPORT(world, FlecsComponentsHttp);

    ecs_set_name_prefix(world, "EcsCivet");
    
    ECS_MODULE(world, FlecsSystemsCivetweb);
    
    ECS_COMPONENT(world, EcsCivetServer);

    ECS_SYSTEM(world, CivetSet, EcsOnSet,
        flecs.components.http.Server,
        ?Server,
        SYSTEM:Hidden);

    ECS_SYSTEM(world, CivetUnset, EcsUnSet,
        Server,
        SYSTEM:Hidden);        

    ECS_SYSTEM(world, CivetRegisterEndpoint, EcsOnSet, 
        flecs.components.http.Endpoint, 
        :Server, 
        SYSTEM:Hidden);

    ECS_TRIGGER(world, CivetDeinit, EcsOnRemove, Server);

    ecs_enable_locking(world, true);
}
