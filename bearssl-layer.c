#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include "bearssl-layer.h"

extern void log_message(const char *fmt, ...);

/* Configuration constants */
#define MAX_CERT_SIZE   4096
#define MAX_CERT_CHAIN  8

/* Global certificate storage */
static const br_rsa_private_key  *g_server_priv_rsa_key;
static const br_x509_certificate *g_cert_chain;
static size_t                     g_cert_chain_amnt;

static unsigned char *g_ca_cert;
static size_t         g_ca_cert_len;

/**
 *
 */
static br_rsa_private_key *copy_rsa_private_key(const br_rsa_private_key *pk)
{
	br_rsa_private_key *outpk;
	outpk = xmalloc(sizeof *pk);
	outpk->n_bitlen = pk->n_bitlen;
	outpk->p        = xblobdup(pk->p, pk->plen);
	outpk->plen     = pk->plen;
	outpk->q        = xblobdup(pk->q, pk->qlen);
	outpk->qlen     = pk->qlen;
	outpk->dp       = xblobdup(pk->dp, pk->dplen);
	outpk->dplen    = pk->dplen;
	outpk->dq       = xblobdup(pk->dq, pk->dqlen);
	outpk->dqlen    = pk->dqlen;
	outpk->iq       = xblobdup(pk->iq, pk->iqlen);
	outpk->iqlen    = pk->iqlen;
	return outpk;
}

/**
 *
 */
static int decode_rsa_key_pem(
	const unsigned char *rsa_key_buf, size_t len,
	const br_rsa_private_key **rk)
{
	const char *errname, *errmsg;
	br_skey_decoder_context dc;
	pem_object *pos;
	size_t amnt_pem;
	int err;
	int ret;

	ret = 0;

	pos = decode_pem(rsa_key_buf, len, &amnt_pem);
	if (!pos) {
		log_message("Unable to decode PEM encoded RSA key!");
		return ret;
	}

	if (!eqstr(pos[0].name, "RSA PRIVATE KEY")
		&& !eqstr(pos[0].name, "EC PRIVATE KEY")
		&& !eqstr(pos[0].name, "PRIVATE KEY"))
	{
		log_message("Not found a proper RSA key!");
		return ret;
	}

	br_skey_decoder_init(&dc);
	br_skey_decoder_push(&dc, pos[0].data, pos[0].data_len);
	err = br_skey_decoder_last_error(&dc);

	if (err != 0) {
		log_message("ERROR (decoding): err=%d\n", err);
		goto out;
	}

	if (br_skey_decoder_key_type(&dc) != BR_KEYTYPE_RSA) {
		log_message("Expected RSA key type!\n");
		goto out;
	}

	*rk = copy_rsa_private_key(br_skey_decoder_get_rsa(&dc));
	ret = 1;
out:
	for (size_t i = 0; pos[i].name; i++)
		free_pem_object_contents(&pos[i]);
	xfree(pos);
	return ret;
}

/**
 *
 */
static int
decode_cert_chain_pem(
	const uint8_t *cert_chain_buf,
	size_t len, const br_x509_certificate **certs, size_t *certs_amnt)
{
	VECTOR(br_x509_certificate) cert_list = VEC_INIT;
	br_x509_certificate *xcs, xc;
	pem_object *pos;
	size_t amnt_pem;

	pos = decode_pem(cert_chain_buf, len, &amnt_pem);
	if (!pos) {
		log_message("Unable to decode PEM encoded certificate chain!");
		return 0;
	}

	for (size_t i = 0; i < amnt_pem; i++) {
		if (!eqstr(pos[i].name, "CERTIFICATE") &&
			!eqstr(pos[i].name, "X509 CERTIFICATE")) {
			continue;
		}

		xc.data     = pos[i].data;
		xc.data_len = pos[i].data_len;
		pos[i].data = NULL;
		VEC_ADD(cert_list, xc);
	}

	for (size_t i = 0; i < amnt_pem; i++)
		free_pem_object_contents(&pos[i]);
	xfree(pos);

	*certs_amnt = VEC_LEN(cert_list);
	if (!*certs_amnt) {
		log_message("No certificate found on TTP_SERVER_CERT_B64!");
		return 0;
	}

	xcs    = VEC_TOARRAY(cert_list);
	*certs = xcs;
	VEC_CLEAR(cert_list);
	return 1;
}

/*
 * Low-level data read callback for the simplified SSL I/O API.
 */
static int
sock_read(void *ctx, unsigned char *buf, size_t len)
{
	ssize_t rlen;
	for (;;) {
		rlen = read(*(int *)ctx, buf, len);
		if (rlen <= 0) {
			if (rlen < 0 && errno == EINTR)
				continue;
			return -1;
		}
		return (int)rlen;
	}
}

/*
 * Low-level data write callback for the simplified SSL I/O API.
 */
static int
sock_write(void *ctx, const unsigned char *buf, size_t len)
{
	ssize_t wlen;
	for (;;) {
		wlen = write(*(int *)ctx, buf, len);
		if (wlen <= 0) {
			if (wlen < 0 && errno == EINTR)
				continue;
			return -1;
		}
		return (int)wlen;
	}
}



/* ========================================================================= */
/* -------------------------- Public routines ------------------------------ */
/* ========================================================================= */

/**
 *
 */
int ssl_init_server_private_key(const uint8_t *pk_buf, size_t len)
{
	if (g_server_priv_rsa_key)
		return 1;
	if (!decode_rsa_key_pem(pk_buf, len, &g_server_priv_rsa_key)) {
		log_message("Failed to decode rsa server key!");
		return 0;
	}
	return 1;
}

/**
 *
 */
int ssl_init_server_certificate_chain(const uint8_t *chain, size_t len)
{
	if (g_cert_chain)
		return 1;
	if (!decode_cert_chain_pem(chain, len, &g_cert_chain, &g_cert_chain_amnt)) {
		log_message("Failed to decode certificate chain!");
		return 0;
	}
	return 1;
}

/**
 * @brief Initializes server context with global certificates
 * @param ctx Server context to initialize
 * @return 1 on success, 0 on failure
 */
int ssl_init_server_context(struct ssl_server_context *ctx, int *sock)
{
	if (!g_cert_chain || !g_server_priv_rsa_key) {
		log_message("Private key and/or certificate chain not configured!");
		return 0;
	}

	/* Initialize server context with global certificates */
	br_ssl_server_init_full_rsa(&ctx->sc,
		g_cert_chain,
		g_cert_chain_amnt,
		g_server_priv_rsa_key);

	/* Set the I/O buffer to our provided array. */
	br_ssl_engine_set_buffer(&ctx->sc.eng, ctx->iobuf, sizeof ctx->iobuf, 1);

	/* Reset the server context, for a new handshake. */
	br_ssl_server_reset(&ctx->sc);

	/* Initialize BearSSL I/O */
	br_sslio_init(&ctx->ioc, &ctx->sc.eng, sock_read, sock, sock_write, sock);

#if 0
	/* Initialize X.509 validator */
	br_x509_minimal_init(&ctx->xc, &br_sha256_vtable, g_ca_cert, g_ca_cert_len);
	br_ssl_engine_set_x509(&ctx->sc.eng, &ctx->xc.vtable);

	/* Require client authentication */
	br_ssl_server_set_client_auth(&ctx->sc, 1);
#endif
	return 1;
}

/**
 *
 */
int ssl_read(struct ssl_server_context *ctx, void *dest, size_t len) {
	return br_sslio_read(&ctx->ioc, dest, len);
}

/**
 *
 */
int ssl_write_all(struct ssl_server_context *ctx, void *src, size_t len) {
	return br_sslio_write_all(&ctx->ioc, src, len);
}

/**
 *
 */
int ssl_flush(struct ssl_server_context *ctx) {
	return br_sslio_flush(&ctx->ioc);
}

/**
 *
 */
int ssl_close(struct ssl_server_context *ctx) {
	br_sslio_close(&ctx->ioc);
	close(*(int *)ctx->ioc.write_context);
}
