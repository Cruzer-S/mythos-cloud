#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>

#include <unistd.h>

#include "Cruzer-S/web-server/web_server.h"
#include "Cruzer-S/web-server/session.h"

#include "Cruzer-S/net-util/net-util.h"

#include "Cruzer-S/logger/logger.h"

#define SERVER_NAME "mythos-cloud"

#define info(...) log(INFO, __VA_ARGS__)
#define warn(...) log(WARN, __VA_ARGS__)
#define errn(...) log(ERRN, __VA_ARGS__), exit(EXIT_FAILURE)

static bool run_server;

static void signal_handler(int signo, siginfo_t *info, void *args)
{
	info("signal raised");
	run_server = false;
}

static void render_error(Session session)
{
	const char *reason;
	struct cjson_value value;
	enum http_status_code code;

	if (session->error == SESSION_ERROR_CLOSED) {
		// nothing to do with it
		return ;
	}

	code = session_errror_to_status_code[session->error];

	reason = http_status_code_string(code);
	warn("[ID %d] error reason: %d (%s)", session->fd, code, reason);

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

	session_render_template(session, code, "error.ctml", object);

	cjson_destroy_object(object);
}

static void request(Session session)
{
	int retval;
	char *request;

	info("[ID %d] request %s: %s", session->fd,
      	      session->header.method, session->header.url);

	if ( !strcmp(session->header.url, "/") )
		request = "index.html";
	else if ( !strcmp(session->header.url, "/favicon.ico") )
		request = "favicon.png";
	else
		request = session->header.url + 1;

	if (strstr(session->header.url, ".ctml")) {
		render_error(session);
		return ;
	}

	switch (http_get_method(&session->header)) {
	case HTTP_REQUEST_GET:
		retval = session_render(session, HTTP_STATUS_CODE_OK, request);
		if (retval == -1) {
			warn("[ID %d] failed to render file: %s",
       		     	     session->fd, request);

			render_error(session);
		}
		break;

	default:
		break;
	}
}

static void connect_session(Session session)
{
	info("[ID %d] session opened", session->fd);
}

static void disconnect_session(Session session)
{
	info("[ID %d] session closed", session->fd);
}

static int init_config(struct web_server_config *config,
			int argc, char *argv[])
{
	if (argc != 6)
		return -1;

	if ( !strcmp(argv[1], "null") || !strcmp(argv[1], "NULL") ) {
		argv[1] = get_hostname(AF_INET);

		if (argv[1] == NULL)
			return -1;
	}

	config->hostname = argv[1];
	config->service = argv[2];

	config->server_name = SERVER_NAME;
	config->basedir = argv[3];

	config->use_ssl = true;
	config->cert_key = argv[4];
	config->priv_key = argv[5];

	config->nthread = 4;

	return 0;
}

static int mask_signal(void)
{
	struct sigaction action;
	sigset_t mask;

	action.sa_flags = 0;
	action.sa_mask = mask;
	action.sa_sigaction = signal_handler;
	if (sigaction(SIGINT, &action, NULL) != 0)
		return -1;

	action.sa_flags = 0;
	action.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &action, NULL) != 0)
		return -1;

	sigfillset(&mask);
	sigdelset(&mask, SIGINT);
	if (pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0)
		return -1;

	return 0;
}

int main(int argc, char *argv[])
{
	WebServer server;
	struct web_server_config config;
	
	logger_initialize();

	if (init_config(&config, argc, argv) == -1)
		errn("failed to init_config()");

	if (mask_signal() == -1)
		errn("failed to mask_signal()");

	server = web_server_create(&config);
	if (server == NULL)
		errn("failed to web_server_create()");

	web_server_register_handler(
		server,
		connect_session,
		request,
		disconnect_session
	);

	info("server running at %s:%s", config.hostname, config.service);
	if (web_server_start(server) == -1)
		errn("failed to web_server_start()");

	for (run_server = true; run_server; )
		sleep(1);

	info("server stopped");

	web_server_stop(server);
	web_server_destroy(server);
	
	info("cleanup done.");

	logger_destroy();

	return 0;
}
