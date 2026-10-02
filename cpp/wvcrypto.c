/* wvcrypto.c — mbedTLS-backed implementation of the flat crypto ABI.
 * See wvcrypto.h. Links against libmbedcrypto.a. */
#include "wvcrypto.h"

#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"
#include "mbedtls/md.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

/* ------------------------------------------------------------------ RNG --- */
/* One process-wide CTR_DRBG, lazily seeded. mbedTLS's entropy source uses the
 * platform CSPRNG (BCrypt/wincrypt on Windows, getrandom on Linux). */
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static int g_rng_ready = 0;

static int ensure_rng(void) {
  if (g_rng_ready) return 0;
  mbedtls_entropy_init(&g_entropy);
  mbedtls_ctr_drbg_init(&g_drbg);
  static const unsigned char pers[] = "openwv-nimony";
  int rc = mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                                 pers, sizeof(pers) - 1);
  if (rc != 0) return -1;
  g_rng_ready = 1;
  return 0;
}

int wvc_random(uint8_t* out, size_t len) {
  if (ensure_rng() != 0) return -1;
  return mbedtls_ctr_drbg_random(&g_drbg, out, len) == 0 ? 0 : -1;
}

/* -------------------------------------------------------------- hashing --- */
int wvc_sha1(const uint8_t* msg, size_t len, uint8_t out[20]) {
  return mbedtls_sha1(msg, len, out) == 0 ? 0 : -1;
}

int wvc_sha256(const uint8_t* msg, size_t len, uint8_t out[32]) {
  return mbedtls_sha256(msg, len, out, 0) == 0 ? 0 : -1;
}

int wvc_hmac_sha256(const uint8_t* key, size_t key_len,
                    const uint8_t* msg, size_t msg_len, uint8_t out[32]) {
  const mbedtls_md_info_t* mi = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!mi) return -1;
  return mbedtls_md_hmac(mi, key, key_len, msg, msg_len, out) == 0 ? 0 : -1;
}

int wvc_aes128_cmac(const uint8_t key[16],
                    const uint8_t* msg, size_t msg_len, uint8_t out[16]) {
  const mbedtls_cipher_info_t* ci =
      mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
  if (!ci) return -1;
  return mbedtls_cipher_cmac(ci, key, 128, msg, msg_len, out) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------ symmetric --- */
int wvc_aes128_ctr(const uint8_t key[16], const uint8_t iv[16],
                   uint8_t* buf, size_t len) {
  mbedtls_aes_context a;
  mbedtls_aes_init(&a);
  int rc = -1;
  unsigned char nonce_counter[16];
  unsigned char stream_block[16];
  size_t nc_off = 0;
  memcpy(nonce_counter, iv, 16);
  memset(stream_block, 0, 16);
  if (mbedtls_aes_setkey_enc(&a, key, 128) == 0 &&
      mbedtls_aes_crypt_ctr(&a, len, &nc_off, nonce_counter, stream_block,
                            buf, buf) == 0) {
    rc = 0;
  }
  mbedtls_aes_free(&a);
  return rc;
}

int wvc_aes128_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                           uint8_t* buf, size_t len) {
  if (len % 16 != 0) return -1;
  mbedtls_aes_context a;
  mbedtls_aes_init(&a);
  int rc = -1;
  unsigned char ivc[16];
  memcpy(ivc, iv, 16);
  if (mbedtls_aes_setkey_dec(&a, key, 128) == 0 &&
      mbedtls_aes_crypt_cbc(&a, MBEDTLS_AES_DECRYPT, len, ivc, buf, buf) == 0) {
    rc = 0;
  }
  mbedtls_aes_free(&a);
  return rc;
}

static int cbc_pkcs7(const uint8_t key[16], const uint8_t iv[16],
                     const uint8_t* in, size_t in_len,
                     uint8_t* out, size_t out_cap, size_t* out_len, int enc) {
  const mbedtls_cipher_info_t* ci =
      mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
  if (!ci) return -1;
  mbedtls_cipher_context_t c;
  mbedtls_cipher_init(&c);
  int rc = -1;
  size_t olen = 0, flen = 0;
  if (mbedtls_cipher_setup(&c, ci) == 0 &&
      mbedtls_cipher_setkey(&c, key, 128,
                            enc ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT) == 0 &&
      mbedtls_cipher_set_padding_mode(&c, MBEDTLS_PADDING_PKCS7) == 0 &&
      mbedtls_cipher_set_iv(&c, iv, 16) == 0 &&
      mbedtls_cipher_reset(&c) == 0) {
    if (in_len > out_cap) goto done;
    if (mbedtls_cipher_update(&c, in, in_len, out, &olen) == 0 &&
        olen <= out_cap &&
        mbedtls_cipher_finish(&c, out + olen, &flen) == 0) {
      *out_len = olen + flen;
      rc = 0;
    }
  }
done:
  mbedtls_cipher_free(&c);
  return rc;
}

int wvc_aes128_cbc_decrypt_pkcs7(const uint8_t key[16], const uint8_t iv[16],
                                 const uint8_t* in, size_t in_len,
                                 uint8_t* out, size_t out_cap, size_t* out_len) {
  return cbc_pkcs7(key, iv, in, in_len, out, out_cap, out_len, 0);
}

int wvc_aes128_cbc_encrypt_pkcs7(const uint8_t key[16], const uint8_t iv[16],
                                 const uint8_t* in, size_t in_len,
                                 uint8_t* out, size_t out_cap, size_t* out_len) {
  return cbc_pkcs7(key, iv, in, in_len, out, out_cap, out_len, 1);
}

/* ------------------------------------------------------------------ RSA --- */
/* Both importers accept a bare PKCS#1 DER key (RSAPrivateKey / RSAPublicKey),
 * which is what .wvd files and Widevine device certs carry. */
static int load_priv(mbedtls_rsa_context* rsa, const uint8_t* der, size_t n) {
  mbedtls_rsa_init(rsa);
  if (mbedtls_rsa_parse_key(rsa, der, n) != 0) return -1;
  if (mbedtls_rsa_complete(rsa) != 0) return -1;
  return 0;
}
static int load_pub(mbedtls_rsa_context* rsa, const uint8_t* der, size_t n) {
  mbedtls_rsa_init(rsa);
  if (mbedtls_rsa_parse_pubkey(rsa, der, n) != 0) return -1;
  return 0;
}

int wvc_rsa_pss_sha1_sign(const uint8_t* der, size_t der_len,
                          const uint8_t* msg, size_t msg_len,
                          uint8_t* sig, size_t sig_cap, size_t* sig_len) {
  if (ensure_rng() != 0) return -1;
  mbedtls_rsa_context rsa;
  if (load_priv(&rsa, der, der_len) != 0) { mbedtls_rsa_free(&rsa); return -1; }
  int rc = -1;
  uint8_t hash[20];
  size_t klen = mbedtls_rsa_get_len(&rsa);
  if (klen <= sig_cap &&
      mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1) == 0 &&
      wvc_sha1(msg, msg_len, hash) == 0 &&
      mbedtls_rsa_rsassa_pss_sign(&rsa, mbedtls_ctr_drbg_random, &g_drbg,
                                  MBEDTLS_MD_SHA1, 20, hash, sig) == 0) {
    *sig_len = klen;
    rc = 0;
  }
  mbedtls_rsa_free(&rsa);
  return rc;
}

int wvc_rsa_pss_sha1_verify(const uint8_t* der, size_t der_len,
                            const uint8_t* msg, size_t msg_len,
                            const uint8_t* sig, size_t sig_len) {
  mbedtls_rsa_context rsa;
  if (load_pub(&rsa, der, der_len) != 0) { mbedtls_rsa_free(&rsa); return -1; }
  int rc = -1;
  uint8_t hash[20];
  if (sig_len == mbedtls_rsa_get_len(&rsa) &&
      mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1) == 0 &&
      wvc_sha1(msg, msg_len, hash) == 0 &&
      mbedtls_rsa_rsassa_pss_verify(&rsa, MBEDTLS_MD_SHA1, 20, hash, sig) == 0) {
    rc = 0;
  }
  mbedtls_rsa_free(&rsa);
  return rc;
}

int wvc_rsa_oaep_sha1_decrypt(const uint8_t* der, size_t der_len,
                              const uint8_t* ct, size_t ct_len,
                              uint8_t* out, size_t out_cap, size_t* out_len) {
  if (ensure_rng() != 0) return -1;
  mbedtls_rsa_context rsa;
  if (load_priv(&rsa, der, der_len) != 0) { mbedtls_rsa_free(&rsa); return -1; }
  int rc = -1;
  size_t olen = 0;
  if (ct_len == mbedtls_rsa_get_len(&rsa) &&
      mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1) == 0 &&
      mbedtls_rsa_rsaes_oaep_decrypt(&rsa, mbedtls_ctr_drbg_random, &g_drbg,
                                     NULL, 0, &olen, ct, out, out_cap) == 0) {
    *out_len = olen;
    rc = 0;
  }
  mbedtls_rsa_free(&rsa);
  return rc;
}

int wvc_rsa_oaep_sha1_encrypt(const uint8_t* der, size_t der_len,
                              const uint8_t* pt, size_t pt_len,
                              uint8_t* out, size_t out_cap, size_t* out_len) {
  if (ensure_rng() != 0) return -1;
  mbedtls_rsa_context rsa;
  if (load_pub(&rsa, der, der_len) != 0) { mbedtls_rsa_free(&rsa); return -1; }
  int rc = -1;
  size_t klen = mbedtls_rsa_get_len(&rsa);
  if (klen <= out_cap &&
      mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1) == 0 &&
      mbedtls_rsa_rsaes_oaep_encrypt(&rsa, mbedtls_ctr_drbg_random, &g_drbg,
                                     NULL, 0, pt_len, pt, out) == 0) {
    *out_len = klen;
    rc = 0;
  }
  mbedtls_rsa_free(&rsa);
  return rc;
}
