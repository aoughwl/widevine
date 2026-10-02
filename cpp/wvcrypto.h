/* wvcrypto.h — flat C crypto ABI the nimony layer imports (importc).
 *
 * Backed by mbedTLS (libmbedcrypto.a). All functions return 0 on success and
 * a negative value on failure. Output buffers are caller-allocated; where an
 * output length is variable the caller passes a capacity and receives the
 * actual length via an out-parameter. No function allocates memory that the
 * caller must free. */
#ifndef WVCRYPTO_H_
#define WVCRYPTO_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- hashing --- */
int wvc_sha1(const uint8_t* msg, size_t len, uint8_t out[20]);
int wvc_sha256(const uint8_t* msg, size_t len, uint8_t out[32]);
int wvc_hmac_sha256(const uint8_t* key, size_t key_len,
                    const uint8_t* msg, size_t msg_len, uint8_t out[32]);

/* AES-128-CMAC (one-shot). key is 16 bytes. */
int wvc_aes128_cmac(const uint8_t key[16],
                    const uint8_t* msg, size_t msg_len, uint8_t out[16]);

/* --- symmetric --- */
/* AES-128-CTR, in-place, 128-bit big-endian counter from the 16-byte initial
 * block `iv`. `len` need not be a multiple of 16. */
int wvc_aes128_ctr(const uint8_t key[16], const uint8_t iv[16],
                   uint8_t* buf, size_t len);

/* AES-128-CBC decrypt in-place, NO padding. `len` must be a multiple of 16. */
int wvc_aes128_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                           uint8_t* buf, size_t len);

/* AES-128-CBC decrypt WITH PKCS7 unpadding. Writes to `out` (cap >= in_len),
 * sets *out_len to the unpadded length. */
int wvc_aes128_cbc_decrypt_pkcs7(const uint8_t key[16], const uint8_t iv[16],
                                 const uint8_t* in, size_t in_len,
                                 uint8_t* out, size_t out_cap, size_t* out_len);

/* AES-128-CBC encrypt WITH PKCS7 padding. `out` cap must be >= in_len + 16. */
int wvc_aes128_cbc_encrypt_pkcs7(const uint8_t key[16], const uint8_t iv[16],
                                 const uint8_t* in, size_t in_len,
                                 uint8_t* out, size_t out_cap, size_t* out_len);

/* --- RSA (all using a PKCS#1 DER key and SHA-1 for PSS/OAEP+MGF1) --- */

/* Sign `msg` (hashed internally with SHA-1) with RSA-PSS using a PKCS#1 DER
 * RSA PRIVATE key. `sig` cap must be >= the modulus size (256 for RSA-2048);
 * *sig_len gets the actual length. */
int wvc_rsa_pss_sha1_sign(const uint8_t* der, size_t der_len,
                          const uint8_t* msg, size_t msg_len,
                          uint8_t* sig, size_t sig_cap, size_t* sig_len);

/* Verify an RSA-PSS/SHA-1 signature over `msg` with a PKCS#1 DER RSA PUBLIC
 * key (bare RSAPublicKey, not SubjectPublicKeyInfo). 0 = valid. */
int wvc_rsa_pss_sha1_verify(const uint8_t* der, size_t der_len,
                            const uint8_t* msg, size_t msg_len,
                            const uint8_t* sig, size_t sig_len);

/* RSA-OAEP/SHA-1 decrypt with a PKCS#1 DER RSA PRIVATE key. */
int wvc_rsa_oaep_sha1_decrypt(const uint8_t* der, size_t der_len,
                              const uint8_t* ct, size_t ct_len,
                              uint8_t* out, size_t out_cap, size_t* out_len);

/* RSA-OAEP/SHA-1 encrypt with a PKCS#1 DER RSA PUBLIC key (bare RSAPublicKey).
 * `out` cap must be >= modulus size. */
int wvc_rsa_oaep_sha1_encrypt(const uint8_t* der, size_t der_len,
                              const uint8_t* pt, size_t pt_len,
                              uint8_t* out, size_t out_cap, size_t* out_len);

/* --- RNG --- */
int wvc_random(uint8_t* out, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* WVCRYPTO_H_ */
