#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>

#include <unistd.h>

#include "Cruzer-S/logger/logger.h"

#include "Cruzer-S/web-server/web_server.h"
#include "Cruzer-S/web-server/web_server_util.h"

#define SERVER_NAME "mythos-cloud"

#define info(...) log(INFO, __VA_ARGS__)
#define warn(...) log(WARN, __VA_ARGS__)
#define errn(...) log(ERRN, __VA_ARGS__), exit(EXIT_FAILURE)

static bool run_server;

static void signal_handler(int signo)
{
	run_server = false;
}

static void render_error(Session session,
			 enum web_server_error error,
			 enum http_status_code code)
{
	const char *reason;

	struct cjson_value value;

	reason = http_status_code_string(code);
	warn("[ID %d] error reason: %d (%s)", session->id, code, reason);

	struct cjson_object *object = cjson_create_object("{}");
	if (object == NULL) {
		warn("failed to cjson_create_object()");
		return ;
	}

	value.type = CJSON_VALUE_TYPE_NUMBER; value.n = code;
	if ( !cjson_add_in_object(object, "error_code", value) ) {
		warn("failed to cjson_add_in_object()");
		return ;
	}

	value.type = CJSON_VALUE_TYPE_STRING; value.s = (char *) reason;
	if ( !cjson_add_in_object(object, "error_message", value) ) {
		warn("failed to cjson_add_in_object()");
		return ;
	}

	ws_render_template(session, code, "error.ctml", object);

	cjson_destroy_object(object);
}

static void error(Session session)
{
	enum web_server_error ws_err = ws_get_session_error(session);
	enum http_status_code ws_code = web_server_error_code(ws_err);

	if (ws_err == WS_ERROR_CLOSED) {
		warn("[ID %d] error reason: closed; do nothing", session->id);
		return ;
	}

	render_error(session, ws_err, ws_code);
}

static void request(Session session)
{
	char *request;

	info("[ID %d] request %s: %s", session->id,
      	      session->header.method, session->header.url);

	if ( !strcmp(session->header.url, "/") )
		request = "index.html";
	else if ( !strcmp(session->header.url, "/favicon.ico") )
		request = "favicon.png";
	else
		request = session->header.url + 1;

	if (strstr(session->header.url, ".ctml")) {
		render_error(
			session,
			WS_ERROR_BAD_REQUEST,
			HTTP_STATUS_CODE_BAD_REQUEST
		);
		return ;
	}

	switch (http_get_method(&session->header)) {
	case HTTP_REQUEST_GET:
		if (ws_render(session, HTTP_STATUS_CODE_OK, request) == -1) {
			warn("[ID %d] failed to render file: %s",
       		     	     session->id, request);

			error(session);
		}
		break;

	default:
		break;
	}
}

static void disconnect(Session session)
{
	info("[ID %d] session closed", session->id);
}

static int init_config(struct web_server_config *config,
			int argc, char *argv[])
{
	if (argc != 6)
		return -1;

	if ( !strcmp(argv[1], "null") || !strcmp(argv[1], "NULL") )
		argv[1] = NULL;

	config->hostname = argv[1];
	config->service = argv[2];

	config->server_name = SERVER_NAME;
	config->basedir = argv[3];

	config->use_ssl = true;
	config->cert_key = argv[4];
	config->priv_key = argv[5];

	return 0;
}

int main(int argc, char *argv[])
{
	WebServer server;
	struct web_server_config config;
	
	logger_initialize();

	sigset_t sigset;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigprocmask(SIG_BLOCK, &sigset, NULL);

	if (init_config(&config, argc, argv) == -1)
		errn("failed to init_config()");

	server = web_server_create(&config);
	if (server == NULL)
		errn("failed to web_server_create()");

	web_server_register_handler(server, request, disconnect);

	info("server running at %s:%s", config.hostname, config.service);
	if (web_server_start(server) == -1)
		exit(1);

	for (run_server = true; run_server; )
		sleep(1);

	info("server stopped");

	web_server_stop(server);
	web_server_destroy(server);
	
	info("cleanup done.");

	logger_destroy();

	return 0;
}
