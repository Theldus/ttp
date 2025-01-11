/*
 * TTP: Tiny TLS Proxy: a very simple TLS proxy server with
 *                      focus on resource consumption.
 * Made by Davidson Francis.
 * This is free and unencumbered software released into the public domain.
 */

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#ifdef USE_BEARSSL
#include "bearssl-layer.h"
#endif

/* Max recv buffer size and log lines. */
#define BUFFER_SIZE  16386
#define MAX_LOG_LINE 1024

/* Socket list fds. */
#define SSL_SOCK_FD       0
#define PLAINTEXT_SOCK_FD 1

extern unsigned char *base64_decode(
	const unsigned char *src, size_t len, size_t *out_len);

/* Global configuration */
static FILE       *g_logfile     = NULL;
static int         g_listen_port = 7171;
static int         g_target_port = 80;
static const char *g_target_host = "127.0.0.1";

/* Required environment variables */
static const char *REQUIRED_ENV_VARS[] = {
	"TTP_SERVER_CERT_B64",
	"TTP_SERVER_KEY_B64",
	"TTP_LOG_PATH",
	"TTP_LISTEN_PORT",
	"TTP_TARGET_PORT",
	"TTP_TARGET_HOST"
};

/**
 * @brief Writes a log message both to stdout and the log file
 * @param fmt Format string
 * @param ... Variable arguments
 */
void log_message(const char *fmt, ...)
{
	char timestamp[32];
	char message[MAX_LOG_LINE];
	time_t now;
	struct tm *timeinfo;
	va_list args;

	/* Get timestamp */
	time(&now);
	timeinfo = localtime(&now);
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

	/* Format message */
	va_start(args, fmt);
	vsnprintf(message, sizeof(message), fmt, args);
	va_end(args);

	/* Write to stdout */
	printf("[%s] %s\n", timestamp, message);

	/* Write to log file if available */
	if (g_logfile) {
		fprintf(g_logfile, "[%s] %s\n", timestamp, message);
		fflush(g_logfile);
	}
}

/**
 * @brief Checks if all required environment variables are set
 * @return 1 if all variables are set, 0 otherwise
 */
static int check_environment(void)
{
	size_t i;
	size_t vars_amnt;
	int missing = 0;

	vars_amnt = sizeof(REQUIRED_ENV_VARS)/sizeof(REQUIRED_ENV_VARS[0]);

	for (i = 0; i < vars_amnt; i++) {
		if (!getenv(REQUIRED_ENV_VARS[i])) {
			log_message("Missing required environment variable: %s",
				REQUIRED_ENV_VARS[i]);
			missing = 1;
		}
	}

	if (!missing)
		return 1;

	log_message("Usage: ttp requires the following environment variables:");
	for (i = 0; i < vars_amnt; i++)
		log_message("  %s", REQUIRED_ENV_VARS[i]);

	log_message(
		"All certificate/key variables should contain base64 encoded data");
	return 0;
}

/**
 * @brief Structure to hold decoded certificate data
 */
struct decoded_cert {
	uint8_t *data;
	size_t len;
};

/**
 * @brief Decodes a base64 environment variable into a decoded_cert structure
 *
 * @param env_var_name Name of the environment variable to decode
 * @param required     Whether this certificate is required
 * @param out_cert     Pointer to store decoded certificate data
 *
 * @return 1 on success, 0 on failure.
 */
static int
decode_cert_from_env(const char *env_var_name, int required,
	struct decoded_cert *out_cert)
{
	const char *b64_data = getenv(env_var_name);

	if (!b64_data) {
		if (!required) {
			out_cert->data = NULL;
			out_cert->len = 0;
			return 1;
		}
		log_message("Required environment variable %s not found", env_var_name);
		return 0;
	}

	out_cert->data = base64_decode((const uint8_t*)b64_data,
		strlen(b64_data), &out_cert->len);
	if (!out_cert->data) {
		log_message("Failed to decode base64 data from %s", env_var_name);
		return 0;
	}

	return 1;
}

/**
 * @brief Safely frees a decoded_cert structure
 */
static void free_decoded_cert(struct decoded_cert *cert)
{
	if (cert) {
		free(cert->data);
		cert->data = NULL;
		cert->len = 0;
	}
}

/**
 * @brief Initializes global certificate storage from environment variables
 * @return 1 on success, 0 on failure
 */
static int init_certificates(void)
{
	struct decoded_cert server_key  = {0};
	struct decoded_cert server_cert = {0};
	struct decoded_cert server_ca   = {0};
	int decode_result;
	int ret;

	ret = 0;

    /* Decode server private key (required) */
	if (decode_cert_from_env("TTP_SERVER_KEY_B64", 1, &server_key) < 0)
		return 0;
    /* Decode server certificate chain (required) */
	if (decode_cert_from_env("TTP_SERVER_CERT_B64", 1, &server_cert) < 0)
		goto cleanup;
    /* Decode server CA (optional) */
	if (decode_cert_from_env("TTP_CA_CERT_B64", 1, &server_ca) < 0)
		goto cleanup;

    /* Initialize SSL components */
	if (!ssl_init_server_private_key(server_key.data, server_key.len)) {
		log_message("Failed to initialize server private key");
		goto cleanup;
	}

	if (!ssl_init_server_certificate_chain(server_cert.data, server_cert.len)) {
		log_message("Failed to initialize server certificate chain");
		goto cleanup;
	}

	if (server_ca.data) {
		if (!ssl_init_server_certificate_authority(server_ca.data, server_ca.len)) {
			log_message("Failed to initialize server certificate authority");
			goto cleanup;
		}
	}

	ret = 1;
cleanup:
    /* Free all decoded certificates */
	free_decoded_cert(&server_key);
	free_decoded_cert(&server_cert);
	free_decoded_cert(&server_ca);
	return ret;
}

/**
 * @brief Creates and connects socket to target server
 *
 * @param host Target host address
 * @param port Target port
 *
 * @return Socket descriptor on success, -1 on failure
 */
static int connect_to_target(const char *host, int port)
{
	struct sockaddr_in target_addr;
	int target_sock;

	target_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (target_sock < 0) {
		log_message("Failed to create target socket (error: %s)",
			strerror(errno));
		return -1;
	}

	memset(&target_addr, 0, sizeof(target_addr));
	target_addr.sin_family = AF_INET;
	target_addr.sin_port   = htons(port);
	inet_pton(AF_INET, host, &target_addr.sin_addr);

	if (connect(target_sock, (struct sockaddr*)&target_addr,
		sizeof(target_addr)) < 0)
	{
		log_message("Failed to connect to target for client (error: %s)",
			strerror(errno));
		close(target_sock);
		return -1;
	}

	return target_sock;
}

/**
 * @brief Write @p len bytes from @p buf to @p conn.
 *
 * Contrary to send(2)/write(2) that might return with less bytes written
 * than specified, this function attempts to write the entire buffer,
 * because... thats the most logical thing to do...
 *
 * @param conn Target file descriptor.
 * @param buf  Buffer to be sent.
 * @param len  Amount of bytes to be sent.
 *
 * @return Returns 0 if success, -1 otherwise.
 */
ssize_t write_all(int conn, const uint8_t *buf, size_t len)
{
	const char *p;
	ssize_t ret;

	if (conn < 0)
		return -1;

	p = buf;
	while (len) {
		ret = write(conn, p, len);
		if (ret == -1)
			return -1;
		p += ret;
		len -= ret;
	}
	return 0;
}

/**
 * @brief Blocks until read some SSL message and then, forward it
 * to the plaintext server.
 *
 * @param ctx             SSL Context.
 * @param plaintext_sock  Plaintext socket fd to send the message.
 *
 * @return Returns 0 on success, -1 on error.
 */
static int handle_ssl_msg(struct ssl_server_context *ctx, int plaintext_sock)
{
	uint8_t buffer[BUFFER_SIZE];
	ssize_t rlen;
	ssize_t wlen;

	rlen = ssl_read(ctx, buffer, sizeof(buffer));
	if (rlen < 0)
		return rlen;

	wlen = write_all(plaintext_sock, buffer, rlen);
	if (wlen < 0) {
		log_message("Write to target failed for client fd=%d", plaintext_sock);
		return -1;
	}

	return 0;
}

/**
 * @brief Blocks until read some plaintext message and then, forward it
 * to the SSL client.
 *
 * @param ctx             SSL Context.
 * @param plaintext_sock  Plaintext socket fd to read the message.
 *
 * @return Returns 0 on success, -1 on error.
 */
static int handle_plaintext_msg(struct ssl_server_context *ctx, int plaintext_sock)
{
	uint8_t buffer[BUFFER_SIZE];
	ssize_t rlen;
	int     wlen;

	rlen = read(plaintext_sock, buffer, sizeof(buffer));
	if (rlen <= 0)
		return -1;

	wlen = ssl_write_all(ctx, buffer, rlen);
	if (wlen != 0) {
		log_message("Write to client failed for fd=%d", plaintext_sock);
		return -1;
	}

	ssl_flush(ctx);
	return 0;
}

/**
 * @brief Handles data forwarding between client (SSL) and target server
 * (plaintext).
 *
 * @param client_ip Client IP for logging
 * @param ssl_ctx   SSL context
 */
static void
do_proxy(const char *client_ip, struct ssl_server_context *ssl_ctx)
{
	struct pollfd pfds[2];
	int plaintext_sock;
	int openfds;
	int r_ev;
	int ret;

	/* Attempt to do the handshake process, including CA auth. */
	if (ssl_handshake(ssl_ctx) < 0)
		goto abort;

	log_message("> Handshake succeeded!");

	/* Connect to target server */
	plaintext_sock = connect_to_target(g_target_host, g_target_port);
	if (plaintext_sock < 0) {
		log_message("Unable to connect to plain-text server!, for client: %s",
			client_ip);
		goto abort;
	}

	openfds = 2;
	pfds[SSL_SOCK_FD].fd           = ssl_ctx->fd;
	pfds[SSL_SOCK_FD].events       = POLLIN;
	pfds[PLAINTEXT_SOCK_FD].fd     = plaintext_sock;
	pfds[PLAINTEXT_SOCK_FD].events = POLLIN;

	log_message("Started forwarding for client %s", client_ip);

	while (poll(pfds, 2, -1) != -1)
	{
		for (int i = 0; i < 2; i++)
		{
			if ((r_ev = pfds[i].revents) != 0) {
				if (r_ev & POLLIN) {
					switch (i) {
					case SSL_SOCK_FD:
						ret = handle_ssl_msg(ssl_ctx, plaintext_sock);
						break;
					case PLAINTEXT_SOCK_FD:
						ret = handle_plaintext_msg(ssl_ctx, plaintext_sock);
						break;
					}

					if (ret < 0)
						goto conn_ended;
				}
				else { /* POLLERR | POLLHUP */
					/* If one of the pairs have disconnected, theres
					 * nothing we can do.. so... aborting everything.
					 */
					goto conn_ended;
				}
			}
		}
	}

conn_ended:
	close(plaintext_sock);
abort:
	ssl_close(ssl_ctx);
	log_message("Connection closed for client %s\n", client_ip);
}

/**
 * @brief Handles a client connection
 * @param ssl_sock SSL Client socket descriptor
 */
static void handle_client(int ssl_sock)
{
	char client_ip[INET_ADDRSTRLEN];
	struct ssl_server_context *ctx;
	struct sockaddr_in addr;
	socklen_t addr_len;
	int plaintext_sock;

	ctx      = xmalloc(sizeof(struct ssl_server_context));
	addr_len = sizeof(addr);

	/* Get client IP */
	getpeername(ssl_sock, (struct sockaddr*)&addr, &addr_len);
	inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));

	log_message("New client connection from %s", client_ip);

	/*
	 * Configure an initial timeout for the handshake.
	 *
	 * The idea of putting a timeout to the handshake process, is to avoid
	 * random non-SSL clients trying to connect and possibly occupying
	 * resources on our server for an indefinite amount of time.
	 */
	ctx->fd         = ssl_sock;
	ctx->timeout_ms = MAX_HANDSHAKE_TIMEOUT_MS;

	/* Initialize SSL */
	if (!ssl_init_server_context(ctx)) {
		log_message("Failed to initialize server context for client %s",
			client_ip);
		ssl_close(ctx);
		return;
	}

	/* Handle data forwarding */
	do_proxy(client_ip, ctx);
}

/**
 * @brief Sets up server socket and binds to port
 * @param port Port to listen on
 * @return Socket descriptor on success, -1 on failure
 */
static int setup_server_socket(int port)
{
	int reuse;
	int server_sock;
	struct sockaddr_in server_addr;

	server_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (server_sock < 0) {
		log_message("Failed to create server socket: %s", strerror(errno));
		return -1;
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family      = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port        = htons(port);

	/* Reuse previous address. */
	reuse = 1;
	if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
		sizeof(reuse)) < 0) {
		log_message("Unable to reuse address!");
	}

	if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
		log_message("Failed to bind: %s", strerror(errno));
		close(server_sock);
		return -1;
	}

	if (listen(server_sock, 5) < 0) {
		log_message("Failed to listen: %s", strerror(errno));
		close(server_sock);
		return -1;
	}

	return server_sock;
}

/**
 * @brief Main function
 */
int main(void)
{
	struct sockaddr_in client_addr;
	int server_sock, client_sock;
	socklen_t client_len;
	const char *log_path;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	/* Check environment variables */
	if (!check_environment())
		return 1;

	/* Initialize logging */
	log_path  = getenv("TTP_LOG_PATH");
	g_logfile = fopen(log_path, "a");

	if (!g_logfile) {
		fprintf(stderr, "Failed to open log file %s: %s\n",
			log_path, strerror(errno));
		return 1;
	}

	/* Get configuration from environment */
	g_listen_port = atoi(getenv("TTP_LISTEN_PORT"));
	g_target_port = atoi(getenv("TTP_TARGET_PORT"));
	g_target_host = getenv("TTP_TARGET_HOST");

	/* Initialize certificates */
	if (!init_certificates())
		goto cleanup_log;

	/* Setup server socket */
	server_sock = setup_server_socket(g_listen_port);
	if (server_sock < 0)
		goto cleanup_log;

	log_message("Tiny TLS Proxy started on port %d", g_listen_port);
	log_message("Forwarding to %s:%d", g_target_host, g_target_port);

	/* Main accept loop */
	while (1) {
		client_len  = sizeof(client_addr);
		client_sock = accept(server_sock, (struct sockaddr*)&client_addr,
			&client_len);

		if (client_sock < 0) {
			log_message("Accept failed: %s", strerror(errno));
			continue;
		}

		/* Handle client in a new process */
		if (fork() == 0) {
			close(server_sock);
			handle_client(client_sock);
			exit(0);
		}
		close(client_sock);
	}
	close(server_sock);

cleanup_log:
	fclose(g_logfile);
	return 1;
}
