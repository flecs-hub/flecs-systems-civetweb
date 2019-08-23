#include <string.h>
#include <flecs_systems_civetweb.h>
#include "civetweb.h"

#define INIT_REQUEST_COUNT (8)


static const ecs_vector_params_t endpoint_param = {
    .element_size = sizeof(EcsHttpEndpoint)
};

static const ecs_vector_params_t entity_param = {
    .element_size = sizeof(ecs_entity_t)
};

/* Server data allocated on heap (not in ECS). This ensures the pointer is
 * stable and cannot change due to data moving around. */
typedef struct CivetServerData {
    struct mg_context *server;

    /* Cache endpoints defined in ECS, so we won't need to access the ECS system
     * when receiving a request, which would not be thread safe as civetweb does
     * not provide the option to manually control threading. */
    ecs_vector_t *endpoints;
    ecs_vector_t *endpoint_entities;
	ecs_os_mutex_t endpoint_lock;

    /* Lock and condition variable protecting access to ECS data */
	ecs_os_mutex_t ecs_lock;
	ecs_os_cond_t ecs_cond;

    /* Number of requests waiting */
    int requests_waiting;

    /* Access to ECS world */
    ecs_world_t *world;
} CivetServerData;

/* ECS server component only contains a pointer to the heap structure */
typedef struct CivetServerComponent {
    CivetServerData *server_data;
} CivetServerComponent;

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
    ut_strbuf buf = UT_STRBUF_INIT;
    ut_strbuf_append(&buf, "HTTP/1.1 %d OK\r\nAccess-Control-Allow-Origin: *\r\n", status);
    if (header) {
        ut_strbuf_appendstr_zerocpy(&buf, header);
    }
    ut_strbuf_appendstr(&buf, "\r\n");
    if (body) ut_strbuf_appendstr_zerocpy(&buf, body);
    char *msg = ut_strbuf_get(&buf);
    mg_write(conn, msg, strlen(msg));
}

static
bool eval_endpoints(EndpointEvalCtx *ctx) {
    EcsHttpReply reply = {.status = 201};
    EcsHttpRequest *request = &ctx->request;
    CivetServerData *server_data = ctx->server_data;
    struct mg_connection *conn = request->ctx;
    const char *r_url = request->url;
    bool handled = false;
    if (r_url[0] == '/') r_url ++;

    EcsHttpEndpoint *buffer = ecs_vector_first(server_data->endpoints);
    ecs_entity_t *entity_buffer = ecs_vector_first(server_data->endpoint_entities);
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

                if (endpoint->synchronous) {
                    ut_ainc(&server_data->requests_waiting);
                    ecs_os_mutex_lock(server_data->ecs_lock);
                }

                ecs_os_dbg("civet: 201: endpoint '/%s' matched", e_url);

                handled = endpoint->action(world, entity, endpoint, request, &reply);

                if (endpoint->synchronous) {
                    if (!ut_adec(&server_data->requests_waiting)) {
                        ecs_os_cond_signal(server_data->ecs_cond);
                    }
                    ecs_os_mutex_unlock(server_data->ecs_lock);
                }

                if (handled) {
                    if (reply.is_file) {
                        mg_send_file(conn, reply.body);
                    } else {
                        do_reply(conn, reply.status, reply.header, reply.body);
                    }
                }
                break;
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


    ecs_os_dbg("civet: %s: uri=%s query=%s", 
        req_info->request_method, req_info->local_uri, req_info->query_string);

    /* Evaluate request for all endpoints for this server */
    ecs_os_mutex_lock(server_data->endpoint_lock);
    bool handled = eval_endpoints(&eval_ctx);
    ecs_os_mutex_unlock(server_data->endpoint_lock);

    if (!handled) {
        do_reply(conn, 404, NULL, NULL);
        ecs_os_dbg("civet: 404: no endpoint found");
    }

    return 1;
}

static
void CivetInit(ecs_rows_t *rows) {
    ecs_world_t *world = rows->world;
    EcsHttpServer *server = ecs_column(rows, EcsHttpServer, 1);
    ecs_type_t TCivetServerComponent = ecs_column_type(rows, 2);

    int i;
    for (i = 0; i < rows->count; i ++) {
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

        ecs_os_dbg("civet: starting server on port %u", server[i].port);

        server_data->world = world;
        server_data->server = mg_start(&callbacks, server_data, options);
        server_data->endpoints = ecs_vector_new(&endpoint_param, 0);
        server_data->endpoint_entities = ecs_vector_new(&entity_param, 0);
        server_data->requests_waiting = 0;
		server_data->endpoint_lock = ecs_os_mutex_new();
		server_data->ecs_lock = ecs_os_mutex_new();
		server_data->ecs_cond = ecs_os_cond_new();

        /* Add component with Civetweb data */
        ecs_set(world, rows->entities[i], CivetServerComponent, {
            .server_data = server_data
        });

        ecs_os_mutex_lock(server_data->ecs_lock);

        /* Set handler for requests */
        mg_set_request_handler(server_data->server, "**", CbOnRequest, server_data);

        /* Set websocket handlers */
        mg_set_websocket_handler(
            server_data->server, "/", CbWsConnect, CbWsReady, CbWsData, CbWsClose, server_data);
    }
}

static
void CivetDeinit(ecs_rows_t *rows) {
    CivetServerComponent *c = ecs_column(rows, CivetServerComponent, 1);
    int i;
    for (i = 0; i < rows->count; i ++) {
        CivetServerData *data = c[i].server_data;
        mg_stop(data->server);
        ecs_os_mutex_unlock(data->ecs_lock);
        ecs_os_mutex_free(data->ecs_lock);
        ecs_os_cond_free(data->ecs_cond);
        ecs_os_free(data);
    }
}

static
void CivetServer(ecs_rows_t *rows) {
    CivetServerComponent *c = ecs_column(rows, CivetServerComponent, 1);
    int i;
    for (i = 0; i < rows->count; i++) {
        CivetServerData *data = c[i].server_data;

        if (data->requests_waiting) {
            ecs_os_mutex_unlock(data->ecs_lock);
            ecs_os_cond_wait(data->ecs_cond, data->ecs_lock);
        }
    }
}

static
ecs_entity_t find_server(
    ecs_world_t *world,
    ecs_entity_t ep,
    ecs_type_t TCivetServerComponent)
{
    ecs_type_t type = ecs_get_type(world, ep);
    ecs_entity_t *array = ecs_vector_first(type);
    uint32_t i, count = ecs_vector_count(type);
 
    for (i = 0; i < count; i ++) {
        ecs_entity_t e = array[i];
        if (e & ECS_CHILDOF) {
            if (ecs_has(world, e & ECS_ENTITY_MASK, CivetServerComponent)) {
                return e & ECS_ENTITY_MASK;
            }
        }
    }

    return 0;
}

static
void CivetRegisterEndpoint(ecs_rows_t *rows) {
    EcsHttpEndpoint *ep = ecs_column(rows, EcsHttpEndpoint, 1);
    ecs_type_t TCivetServerComponent = ecs_column_type(rows, 2);

    int i;
    for (i = 0; i < rows->count; i ++) {
        ecs_entity_t entity = rows->entities[i];

        ecs_entity_t server = find_server(rows->world, entity, TCivetServerComponent);
        if (server) {
            CivetServerComponent *c = ecs_get_ptr(rows->world, server, CivetServerComponent);
            CivetServerData *data = c->server_data;

            ecs_os_mutex_lock(data->endpoint_lock);
            EcsHttpEndpoint *new_ep = ecs_vector_add(&data->endpoints, &endpoint_param);
            *new_ep = ep[i];
            ecs_entity_t *new_entity = ecs_vector_add(&data->endpoint_entities, &entity_param);
            *new_entity = entity;
            ecs_os_mutex_unlock(data->endpoint_lock);
        } else {
            ecs_os_warn("no server found for endpoint '%s'", ep->url);
        }
    }
}

void FlecsSystemsCivetwebImport(
    ecs_world_t *world,
    int flags)
{
    ECS_IMPORT(world, FlecsComponentsHttp, 0);
    ECS_MODULE(world, FlecsSystemsCivetweb);

    ECS_COMPONENT(world, CivetServerComponent);
    ECS_SYSTEM(world, CivetInit, EcsOnSet, EcsHttpServer, .CivetServerComponent, SYSTEM.EcsHidden);
    ECS_SYSTEM(world, CivetRegisterEndpoint, EcsOnSet, EcsHttpEndpoint, .CivetServerComponent, SYSTEM.EcsHidden);
    ECS_SYSTEM(world, CivetDeinit, EcsOnRemove, CivetServerComponent, SYSTEM.EcsHidden);
    ECS_SYSTEM(world, CivetServer, EcsOnUpdate, CivetServerComponent, SYSTEM.EcsHidden);

    ECS_SET_ENTITY(CivetServer);
}
