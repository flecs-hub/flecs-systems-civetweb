#include <string.h>
#include <include/civetweb.h>
#include "civetweb.h"
#include <pthread.h>

#define INIT_REQUEST_COUNT (8)

typedef struct CivetwebServerCtx {
    EcsWorld *world;
    EcsHandle server_entity;
    EcsHandle data_component;
    EcsHandle eval_endpoint_system;
} CivetwebServerCtx;

typedef struct CivetwebServerData {
    struct mg_context *server;
    pthread_mutex_t lock;
    CivetwebServerCtx *ctx;
} CivetwebServerData;

static
EcsHttpMethod MethodFromStr(
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

typedef struct EndpointEvalCtx {
    EcsHttpRequest request;
    CivetwebServerData *server_data;
} EndpointEvalCtx;

static
int CbOnRequest(
    struct mg_connection *conn,
    void *cbdata)
{
    const struct mg_request_info *req_info = mg_get_request_info(conn);
    EcsHttpMethod method = MethodFromStr(req_info->request_method);
    CivetwebServerCtx *ctx = cbdata;
    CivetwebServerData *data = ecs_get_ptr(
        ctx->world, ctx->server_entity, ctx->data_component);

    EndpointEvalCtx eval_ctx = {
        .request = {
            .server = ctx->server_entity,
            .method = method,
            .url = req_info->local_uri,
            .params = req_info->query_string,
            .ctx = conn
        },
        .server_data = data
    };

    /* Evaluate request for all endpoints for this server */
    EcsHandle endpoint = ecs_run_system(
        ctx->world, ctx->eval_endpoint_system, 0, ctx->server_entity, &eval_ctx);

    if (!endpoint) {
        do_reply(conn, 404, NULL, NULL);
    }

    return 1;
}

static
void CivetEvalEndpoints(EcsRows *rows) {
    EcsHttpReply reply = {.status = 201};
    EndpointEvalCtx *ctx = rows->param;
    EcsHttpRequest *request = &ctx->request;
    struct mg_connection *conn = request->ctx;
    const char *r_url = request->url;
    if (r_url[0] == '/') r_url ++;

    void *row;
    for (row = rows->first; row < rows->last; row = ecs_next(rows, row)) {
        EcsHttpEndpoint *endpoint = ecs_column(rows, row, 0);
        char *e_url = endpoint->url;
        if (e_url[0] == '/') e_url ++;
        uint32_t e_url_len = strlen(e_url);

        if (!strncmp(e_url, r_url, e_url_len)) {
            const char *orig_r_url = r_url;
            r_url = r_url + e_url_len;

            if (!r_url[0] || r_url[0] == '/' || r_url == orig_r_url) {
                EcsHandle entity = ecs_entity(row);
                EcsWorld *world = rows->world;
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
                    pthread_mutex_lock(&ctx->server_data->lock);
                }

                if (endpoint->action(world, entity, endpoint, request, &reply))
                {
                    if (endpoint->synchronous) {
                        pthread_mutex_unlock(&ctx->server_data->lock);
                    }

                    if (reply.is_file) {
                        mg_send_file(conn, reply.body);
                    } else {
                        do_reply(conn, reply.status, reply.header, reply.body);
                    }
                    rows->interrupted_by = entity;
                    break;
                }

                if (endpoint->synchronous) {
                    pthread_mutex_unlock(&ctx->server_data->lock);
                }
            } else {
                continue;
            }
        }
    }
}

static
void CivetInit(EcsRows *rows) {
    void *row;
    EcsWorld *world = rows->world;

    for (row = rows->first; row < rows->last; row = ecs_next(rows, row)) {
        EcsHandle entity = ecs_entity(row);
        EcsHttpServer *server = ecs_column(rows, row, 0);
        char port[15];
        sprintf(port, "%u", server->port);

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
        EcsHandle CivetwebServerData_h = ecs_lookup(world,"CivetwebServerData");
        CivetwebServerCtx *ctx = malloc(sizeof(CivetwebServerCtx));
        ctx->world = world;
        ctx->server_entity = entity;
        ctx->data_component = CivetwebServerData_h;
        ctx->eval_endpoint_system = ecs_lookup(world, "CivetEvalEndpoints");

        struct mg_context *cv_server = mg_start(
            &callbacks, ctx, options);

        /* Protect app state (unlocked/locked by CivetwebServer system) */
        pthread_mutex_t lock;
        pthread_mutex_init(&lock, NULL);
        pthread_mutex_lock(&lock);

        /* Add component with Civetweb data */
        ecs_set(world, entity, CivetwebServerData, {
            .server = cv_server,
            .lock = lock,
            .ctx = ctx
        });

        /* Set handler for requests */
        mg_set_request_handler(cv_server, "**", CbOnRequest, ctx);

        /* Set websocket handlers */
        mg_set_websocket_handler(
            cv_server, "/", CbWsConnect, CbWsReady, CbWsData, CbWsClose, ctx);
    }
}

static
void CivetDeinit(EcsRows *rows) {
    void *row;
    for (row = rows->first; row < rows->last; row = ecs_next(rows, row)) {
        CivetwebServerData *data = ecs_column(rows, row, 0);
        mg_stop(data->server);
        free(data->ctx);
        pthread_mutex_unlock(&data->lock);
    }
}

static
void CivetServer(EcsRows *rows) {
    void *row;
    for (row = rows->first; row < rows->last; row = ecs_next(rows, row)) {
        CivetwebServerData *data = ecs_column(rows, row, 0);
        pthread_mutex_unlock(&data->lock);

        /* Let workers access state */
        ut_sleep(0, 1000);

        pthread_mutex_lock(&data->lock);
    }
}

void EcsSystemsCivetweb(
    EcsWorld *world,
    int flags,
    void *handles_out)
{
    EcsSystemsCivetwebHandles *handles = handles_out;

    ECS_IMPORT(world, EcsComponentsHttp, 0);
    ECS_COMPONENT(world, CivetwebServerData);
    ECS_SYSTEM(world, CivetInit, EcsOnSet, EcsHttpServer);
    ECS_SYSTEM(world, CivetDeinit, EcsOnRemove, CivetwebServerData);
    ECS_SYSTEM(world, CivetServer, EcsOnFrame, CivetwebServerData);
    ECS_SYSTEM(world, CivetEvalEndpoints, EcsOnDemand, EcsHttpEndpoint);

    ecs_add(world, CivetInit_h, EcsHidden_h);
    ecs_add(world, CivetDeinit_h, EcsHidden_h);
    ecs_add(world, CivetServer_h, EcsHidden_h);
    ecs_add(world, CivetEvalEndpoints_h, EcsHidden_h);

    handles->CivetwebServer = CivetServer_h;
}
