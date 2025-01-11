/*
 * TTP: Tiny TLS Proxy: a very simple TLS proxy server with
 *                      focus on resource consumption.
 * Made by Davidson Francis.
 * This is free and unencumbered software released into the public domain.
 */

#ifndef BEARSSL_LAYER
#define BEARSSL_LAYER

	#include <bearssl.h>
	#include "brssl.h"
	#include <stdint.h>

	/* Max timeout between recv()'s during SSL handshake. */
	#define MAX_HANDSHAKE_TIMEOUT_MS 2500

	/* Subject elements. */
	enum {
		ELT_C,
		ELT_ST,
		ELT_L,
		ELT_O,
		ELT_OU,
		ELT_CN,
		NUM_ELTS
	};

	/**
	 * @brief Single subject element.
	 */
	struct subject {
		char C[3];
		char ST[129];
		char L[129];
		char O[65];
		char OU[65];
		char CN[65];
	};

	/**
	 * @brief Global server context for BearSSL
	 */
	struct ssl_server_context {
		br_ssl_server_context   sc;
		br_x509_minimal_context xc;
		uint8_t                 iobuf[BR_SSL_BUFSIZE_BIDI];
		br_sslio_context        ioc;

		/* Certificate. */
		const br_x509_class  *x509_vtable;
		struct subject  sub;
		br_name_element subject_elts[NUM_ELTS];

		/* Connection data. */
		int fd;
		int timeout_ms;
	};

	int ssl_init_server_private_key(const uint8_t *pk_buf, size_t len);
	int ssl_init_server_certificate_chain(const uint8_t *chain, size_t len);
	int ssl_init_server_certificate_authority(const uint8_t *ca_buf, size_t len);
	int ssl_init_server_context(struct ssl_server_context *ctx);
	int ssl_read(struct ssl_server_context *ctx, void *dest, size_t len);
	int ssl_write_all(struct ssl_server_context *ctx, void *src, size_t len);
	int ssl_flush(struct ssl_server_context *ctx);
	int ssl_close(struct ssl_server_context *ctx);
	int ssl_handshake(struct ssl_server_context *ctx);

#endif
