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
static const private_key         *g_server_priv_key;
static const br_x509_certificate *g_cert_chain;
static size_t                     g_cert_chain_amnt;

/* CA. */
static const br_x509_certificate  *g_ca;
static const br_x509_trust_anchor *g_trust_anchor;

/**
 * @brief Provided an RSA key, do a full copy (on heap) and save it
 * in @p d_pk.
 *
 * @param s_sk Private key to be copied.
 * @param d_pk Pointer to where will store the newly allocated PK.
 *             Please note that the 'br_rsa_private_key' is not allocated!
 *
 * @return Returns @p d_pk.
 */
static br_rsa_private_key *
copy_rsa_private_key(const br_rsa_private_key *s_pk, br_rsa_private_key *d_pk)
{
	br_rsa_private_key *outpk = d_pk;
	outpk->n_bitlen = s_pk->n_bitlen;
	outpk->p        = xblobdup(s_pk->p, s_pk->plen);
	outpk->plen     = s_pk->plen;
	outpk->q        = xblobdup(s_pk->q, s_pk->qlen);
	outpk->qlen     = s_pk->qlen;
	outpk->dp       = xblobdup(s_pk->dp, s_pk->dplen);
	outpk->dplen    = s_pk->dplen;
	outpk->dq       = xblobdup(s_pk->dq, s_pk->dqlen);
	outpk->dqlen    = s_pk->dqlen;
	outpk->iq       = xblobdup(s_pk->iq, s_pk->iqlen);
	outpk->iqlen    = s_pk->iqlen;
	return outpk;
}

/**
 * @brief Provided an EC key, do a full copy (on heap) and save it
 * in @p d_pk.
 *
 * @param s_sk Private key to be copied.
 * @param d_pk Pointer to where will store the newly allocated PK.
 *             Please note that the 'br_ec_private_key' is not allocated!
 *
 * @return Returns @p d_pk.
 */
static br_ec_private_key *
copy_ec_private_key(const br_ec_private_key *s_pk, br_ec_private_key *d_pk)
{
	br_ec_private_key *outpk = d_pk;
	outpk->curve = s_pk->curve;
	outpk->x     = xblobdup(s_pk->x, s_pk->xlen);
	outpk->xlen  = s_pk->xlen;
	return outpk;
}

/**
 * @brief Provided a private key in @p src_pk (whether RSA or EC), do
 * a full copy on heap and return its pointer.
 *
 * @param Private key to be copied.
 *
 * @return Returns the address of the newly allocated private key.
 */
static private_key *copy_private_key(const private_key *src_pk)
{
	private_key *d_pk;
	d_pk           = xmalloc(sizeof *d_pk);
	d_pk->key_type = src_pk->key_type;
	if (d_pk->key_type == BR_KEYTYPE_RSA)
		copy_rsa_private_key(&src_pk->key.rsa, &d_pk->key.rsa);
	else if (d_pk->key_type == BR_KEYTYPE_EC)
		copy_ec_private_key(&src_pk->key.ec, &d_pk->key.ec);
	else {
		log_message("Unknow private key, I can't proceed!");
		exit(0);
	}
	return d_pk;
}

/**
 * @brief Decodes a PEM-encoded private key into a private_key structure.
 *
 * @param rsa_key_buf Buffer containing the PEM-encoded private key.
 * @param len         Length of the buffer.
 * @param rpk         Output parameter to store the decoded private key.
 *
 * @return 1 on success, 0 on failure.
 */
static int decode_key_pem(
	const unsigned char *rsa_key_buf, size_t len, const private_key **rpk)
{
	br_skey_decoder_context dc;
	pem_object *pos;
	size_t amnt_pem;
	private_key pk;
	int key_type;
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
		log_message("Not found a proper private key!");
		return ret;
	}

	br_skey_decoder_init(&dc);
	br_skey_decoder_push(&dc, pos[0].data, pos[0].data_len);
	err = br_skey_decoder_last_error(&dc);

	if (err != 0) {
		log_message("ERROR (decoding): err=%d\n", err);
		goto out;
	}

	key_type    = br_skey_decoder_key_type(&dc);
	pk.key_type = key_type;

	/* Temporary shallow copy here. */
	if (key_type == BR_KEYTYPE_RSA)
		memcpy(&pk.key.rsa, br_skey_decoder_get_rsa(&dc), sizeof(pk.key.rsa));
	else if (key_type == BR_KEYTYPE_EC)
		memcpy(&pk.key.ec, br_skey_decoder_get_ec(&dc), sizeof(pk.key.ec));
	else {
		log_message("Unkown key type found!, aborting...!");
		exit(0);
	}

	/* Fully duplicate the private key in memory. */
	*rpk = copy_private_key(&pk);
	ret = 1;
out:
	for (size_t i = 0; pos[i].name; i++)
		free_pem_object_contents(&pos[i]);
	xfree(pos);
	return ret;
}

/**
 * @brief Decodes a PEM-encoded certificate chain into a list of certificates.
 *
 * @param cert_chain_buf Buffer containing the PEM-encoded certificate chain.
 * @param len            Length of the buffer.
 * @param certs          Output parameter to store the array of decoded certificates.
 * @param certs_amnt     Output parameter to store the number of certificates.
 *
 * @return 1 on success, 0 on failure.
 */
static int
decode_cert_chain_pem(const uint8_t *cert_chain_buf, size_t len,
	const br_x509_certificate **certs, size_t *certs_amnt)
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
 * @brief Low-level data read callback for the simplified SSL I/O API.
 *
 * This function optionally blocks up to s_ctx->timeout_ms in order to cancel
 * long connections.
 *
 * @param ctx SSL context.
 * @param buf Destination buffer.
 * @param len Destination buffer size/max amount to read.
 *
 * @return Returns -1 if error and/or timeout, 0 if success.
 */
static int sock_read(void *ctx, unsigned char *buf, size_t len)
{
	struct ssl_server_context *s_ctx = ctx;
	struct pollfd pfd;
	ssize_t rlen;
	int ret;

	/* Fail early if there is already an error. */
	if (s_ctx->sock_error)
		return -1;

	pfd.fd     = s_ctx->fd;
	pfd.events = POLLIN;
	errno      = 0;

	for (;;) {
		ret = poll(&pfd, 1, s_ctx->timeout_ms);
		if (ret <= 0) {
			if (ret == 0) {
				log_message("Timedout, aborting connection...");
				return -1;
			}
			if (errno == EINTR) {
				errno = 0;
				continue;
			}
			s_ctx->sock_error = 1;
			return -1;
		}

		rlen = read(s_ctx->fd, buf, len);
		if (rlen <= 0) {
			if (rlen < 0 && errno == EINTR) {
				errno = 0;
				continue;
			}
			s_ctx->sock_error = 1;
			return -1;
		}
		return (int)rlen;
	}
}

/*
 * @brief Low-level data write callback for the simplified SSL I/O API.
 *
 * @param ctx SSL context.
 * @param buf Destination buffer.
 * @param len Destination buffer size/max amount to read.
 *
 * @return Returns -1 if error and/or timeout, 0 if success.
 */
static int sock_write(void *ctx, const unsigned char *buf, size_t len)
{
	struct ssl_server_context *s_ctx = ctx;
	ssize_t wlen;

	/* Fail early if there is already an error. */
	if (s_ctx->sock_error)
		return -1;

	for (;;) {
		wlen = write(s_ctx->fd, buf, len);
		if (wlen <= 0) {
			if (wlen < 0 && errno == EINTR)
				continue;
			s_ctx->sock_error = 1;
			return -1;
		}
		return (int)wlen;
	}
}

/**
 * @brief Configure the x509 certificate validation.
 *
 * @param ctx SSL Context.
 *
 * @return Always 1.
 */
static int configure_x509(struct ssl_server_context *ctx)
{
    /* Define a structure to hold OID and corresponding field info */
	struct dn_field_info {
		const uint8_t *oid;
		void *buf;
		size_t size;
		int index;
	};

    /* Array mapping DN fields to their OIDs and buffers */
	const struct dn_field_info fields[NUM_ELTS] = {
		{ (const uint8_t*)"\x03\x55\x04\x06", ctx->sub.C,  sizeof(ctx->sub.C),  ELT_C  },
		{ (const uint8_t*)"\x03\x55\x04\x08", ctx->sub.ST, sizeof(ctx->sub.ST), ELT_ST },
		{ (const uint8_t*)"\x03\x55\x04\x07", ctx->sub.L,  sizeof(ctx->sub.L),  ELT_L  },
		{ (const uint8_t*)"\x03\x55\x04\x0a", ctx->sub.O,  sizeof(ctx->sub.O),  ELT_O  },
		{ (const uint8_t*)"\x03\x55\x04\x0b", ctx->sub.OU, sizeof(ctx->sub.OU), ELT_OU },
		{ (const uint8_t*)"\x03\x55\x04\x03", ctx->sub.CN, sizeof(ctx->sub.CN), ELT_CN }
	};

    /* Configure each DN element */
	for (int i = 0; i < NUM_ELTS; i++) {
		ctx->subject_elts[fields[i].index] = (br_name_element) {
			.oid = fields[i].oid,
			.buf = fields[i].buf,
			.len = fields[i].size
		};
	}

	/* Initialize X.509 validator with trust anchor */
	br_x509_minimal_init_full(&ctx->xc, g_trust_anchor, 1);
    /* Set up name elements in the X.509 context */
	br_x509_minimal_set_name_elements(&ctx->xc, ctx->subject_elts, NUM_ELTS);
    /* Setup client certificate authentication if enabled. */
	if (g_trust_anchor)
		br_ssl_server_set_trust_anchor_names_alt(&ctx->sc, g_trust_anchor, 1);

	br_ssl_engine_set_x509(&ctx->sc.eng, &ctx->xc.vtable);
	return 1;
}

/**
 * @brief For a given SSL Context in @p ctx, dumps the info gathered
 * for a client authenticated via certificate.
 *
 * @param ctx SSL Context.
 *
 * @note This should be called only after a successful handshake.
 */
static void print_subject(const struct ssl_server_context *ctx)
{
	static const char elem[][3] = {"C","ST","L","O","OU","CN"};
	const br_name_element *elts;

	log_message("Subject: ");
	elts = ctx->subject_elts;
	for (int i = 0; i < NUM_ELTS; i++) {
		if (elts[i].status <= 0)
			continue;
		log_message("  %s=(%s)", elem[i], elts[i].buf);
	}
}

/**
 * @brief This is an amalgamation of br_ssl_server_init_full_rsa()
 * and br_ssl_server_init_full_ec() with sane cypher suites
 * and only TLS v1.2, to make Qualys SSL Server Test happy.
 *
 * This accepts both RSA and EC private key.
 *
 * @param ctx SSL Server Context.
 *
 * @return Always 1.
 */
static int init_ssl_with_sane_algs(struct ssl_server_context *ctx)
{
	static uint16_t suites[3];
	/*
	 * Based on the original BearSSL's list (ssl_server_full_rsa.c)
	 * but filtered with only 'safe' algorithms. The 'safe' criteria
	 * is the one used on the results I got on Qualys SSL Server Test
	 */

	/* Choose the suites accordingly with the key used. */
	if (g_server_priv_key->key_type == BR_KEYTYPE_RSA) {
		suites[0] = BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
		suites[1] = BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
		suites[2] = BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
	} else {
		suites[0] = BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
		suites[1] = BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
		suites[2] = BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
	}

	/*
	 * All hash functions are activated.
	 * Note: the X.509 validation engine will nonetheless refuse to
	 * validate signatures that use MD5 as hash function.
	 */
	static const br_hash_class *hashes[] = {
		&br_md5_vtable,
		&br_sha1_vtable,
		&br_sha224_vtable,
		&br_sha256_vtable,
		&br_sha384_vtable,
		&br_sha512_vtable
	};

	/*
	 * Reset server context and set only TLS 1.2 as supported.
	 */
	br_ssl_server_zero(&ctx->sc);
	br_ssl_engine_set_versions(&ctx->sc.eng, BR_TLS12, BR_TLS12);

	/*
	 * Set suites and elliptic curve implementation (for ECDHE).
	 */
	br_ssl_engine_set_suites(&ctx->sc.eng, suites,
		(sizeof suites) / (sizeof suites[0]));
	br_ssl_engine_set_default_ec(&ctx->sc.eng);

	/*
	 * Set the "server policy": handler for the certificate chain
	 * and private key operations.
	 */
	if (g_server_priv_key->key_type == BR_KEYTYPE_RSA) {
		br_ssl_server_set_single_rsa(&ctx->sc, g_cert_chain, g_cert_chain_amnt,
			&g_server_priv_key->key.rsa,
			BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN,
			br_rsa_private_get_default(),
			br_rsa_pkcs1_sign_get_default());
	} else {
		br_ssl_server_set_single_ec(&ctx->sc, g_cert_chain, g_cert_chain_amnt,
			&g_server_priv_key->key.ec,
			BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN,
			BR_KEYTYPE_EC,
			br_ssl_engine_get_ec(&ctx->sc.eng),
			br_ecdsa_i15_sign_asn1); /* Assuming BR_LOMUL defined. */
	}

	/*
	 * Set supported hash functions.
	 */
	for (int id = br_md5_ID; id <= br_sha512_ID; id ++) {
		const br_hash_class *hc;
		hc = hashes[id - 1];
		br_ssl_engine_set_hash(&ctx->sc.eng, id, hc);
	}

	/*
	 * Set the PRF implementations.
	 */
	br_ssl_engine_set_prf10(&ctx->sc.eng, &br_tls10_prf);
	br_ssl_engine_set_prf_sha256(&ctx->sc.eng, &br_tls12_sha256_prf);
	br_ssl_engine_set_prf_sha384(&ctx->sc.eng, &br_tls12_sha384_prf);

	/*
	 * Symmetric encryption.
	 */
	br_ssl_engine_set_default_aes_cbc(&ctx->sc.eng);
	br_ssl_engine_set_default_aes_ccm(&ctx->sc.eng);
	br_ssl_engine_set_default_aes_gcm(&ctx->sc.eng);
	br_ssl_engine_set_default_des_cbc(&ctx->sc.eng);
	br_ssl_engine_set_default_chapol(&ctx->sc.eng);
	return 1;
}

/* ========================================================================= */
/* -------------------------- Public routines ------------------------------ */
/* ========================================================================= */

/**
 * @brief Decode a PEM-encoded private key (wether RSA or EC) and
 * saves the final result for later processing.
 *
 * @param pk_buf PEM-encoded server private key.
 * @param len    Length (in bytes) of @p pk_buf.
 *
 * @return Retuns 1 if success, 0 otherwise.
 */
int ssl_init_server_private_key(const uint8_t *pk_buf, size_t len)
{
	if (g_server_priv_key)
		return 1;
	if (!decode_key_pem(pk_buf, len, &g_server_priv_key)) {
		log_message("Failed to decode rsa server key!");
		return 0;
	}
	return 1;
}

/**
 * @brief Decodes a PEM-encoded certificate chain and saves the final
 * result for later processing.
 *
 * @param chain  PEM-encoded server certificate chain.
 * @param len    Length (in bytes) of @p chain.
 *
 * @return Retuns 1 if success, 0 otherwise.
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
 * @brief Decodes a PEM-encoded certificate authority and saves the final
 * result for later processing.
 *
 * @param ca_buf PEM-encoded server certificate authority.
 * @param len    Length (in bytes) of @p chain.
 *
 * @return Retuns 1 if success, 0 otherwise.
 *
 * @note This certificate is used for client authentication. If none is passed,
 * then client authentication is disabled.
 */
int ssl_init_server_certificate_authority(const uint8_t *ca_buf, size_t len)
{
	size_t ca_amnt;
	if (g_ca)
		return 1;

	/* The decode is pretty much the same as in the certificate
	 * but we ignore the length here, since I'm expecting
	 * to be always 1. */
	if (!decode_cert_chain_pem((const uint8_t*)ca_buf, len, &g_ca, &ca_amnt)) {
		log_message("Failed to decode certificate CA!");
		return 0;
	}
	if (ca_amnt > 1) {
		log_message("CA amnt greater than 1...");
		return 0;
	}

	/* Convert our certificate to trust anchor. */
	g_trust_anchor = certificate_to_trust_anchor((br_x509_certificate *)g_ca);
	if (!g_trust_anchor) {
		log_message("Unable to convert CA certificate to trust anchor...");
		return 0;
	}

	return 1;
}

/**
 * @brief Initializes server context with global certificates.
 *
 * @param ctx         Server context to initialize
 * @param chacha_only If not zero, use only ChaCha20 as the cypher suite.
 *
 * @return 1 on success, 0 on failure
 */
int ssl_init_server_context(struct ssl_server_context *ctx, int chacha_only)
{
    /* Validate required certificates and keys are present */
    if (!g_cert_chain || !g_server_priv_key) {
        log_message("Private key and/or certificate chain not configured!");
        return 0;
    }

    /* === Server Context Initialization === */
	if (!chacha_only) {
		init_ssl_with_sane_algs(ctx);
	} else {
		if (g_server_priv_key->key_type == BR_KEYTYPE_RSA) {
			br_ssl_server_init_mine2c(
				&ctx->sc,
				g_cert_chain,
				g_cert_chain_amnt,
				&g_server_priv_key->key.rsa);
		} else {
			br_ssl_server_init_minf2c(
				&ctx->sc,
				g_cert_chain,
				g_cert_chain_amnt,
				&g_server_priv_key->key.ec);
		}
	}

    /* === Certificate Validation Setup === */
    configure_x509(ctx);

    /* === Cryptographic Operations Setup === */
    /* Set default signature verification algorithms */
    br_ssl_engine_set_default_rsavrfy(&ctx->sc.eng);
    br_ssl_engine_set_default_ec(&ctx->sc.eng);

    /* === I/O and Buffer Setup === */
    /* Configure engine buffer */
    br_ssl_engine_set_buffer(&ctx->sc.eng, ctx->iobuf, sizeof ctx->iobuf, 1);
    /* Reset server context for new handshake */
    br_ssl_server_reset(&ctx->sc);
    /* Initialize BearSSL I/O with socket callbacks */
    br_sslio_init(&ctx->ioc, &ctx->sc.eng, sock_read, ctx, sock_write, ctx);
    return 1;
}

/**
 * @brief Reads an already decrypted message from client, specified in @p ctx.
 *
 * @param ctx  SSL context.
 * @param dest Destination buffer.
 * @param len  Amount of bytes to read.
 *
 * @return Returns the amount of bytes read if success, -1 otherwise.
 */
int ssl_read(struct ssl_server_context *ctx, void *dest, size_t len)
{
	const char *msg;
	int ret;
	int err;

	ret = br_sslio_read(&ctx->ioc, dest, len);
	if (ret < 0) {
		/* Check if error. */
		err = ctx->sc.eng.err;
		if (err != BR_ERR_OK) {
			msg = find_error_name(err, &msg);
			log_message("Disconnected due to: (%s)", msg);
		}
	}
	return ret;
}

/**
 * @brief Writes a (to be encrypted) buffer specified in @p src into
 * the client in @p ctx of length @p len.
 *
 * @param ctx SSL context.
 * @param src Source buffer to be sent.
 * @param len Source buffer length.
 *
 * @return Returns 0 if success, -1 otherwise.
 */
int ssl_write_all(struct ssl_server_context *ctx, void *src, size_t len) {
	return br_sslio_write_all(&ctx->ioc, src, len);
}

/**
 * @brief Ensures all data has been sent.
 *
 * @return Returns 0 if success, -1 if error.
 */
int ssl_flush(struct ssl_server_context *ctx) {
	return br_sslio_flush(&ctx->ioc);
}

/**
 * @brief Closes an underlying SSL connection provided in @p ctx.
 * @return Always 0.
 */
int ssl_close(struct ssl_server_context *ctx) {
	/* Do a clean close only if the SSL socket is still working. */
	if (!ctx->sock_error)
		br_sslio_close(&ctx->ioc);

	close(*(int *)ctx->ioc.write_context);
	return 0;
}

/**
 * @brief Blocks until all the initial SSL handshake is done
 * and the server is ready to send/receive messages.
 *
 * @param ctx SSL context.
 *
 * @return Returns 0 if success, -1 otherwise.
 */
int ssl_handshake(struct ssl_server_context *ctx) {
	const char *msg;
	int ret;
	int err;

	ret = br_sslio_flush(&ctx->ioc);
	if (ret < 0) {
		/* Check if error. */
		err = ctx->sc.eng.err;
		if (err != BR_ERR_OK) {
			msg = find_error_name(err, &msg);
			log_message("Unable to handshake due to: (%s)", msg);
			return ret;
		}
	}

	/* If succeeded, show the logged user (if any)
	 * and disable timeout. */
	if (g_trust_anchor)
		print_subject(ctx);

	ctx->timeout_ms = -1;
	return ret;
}
