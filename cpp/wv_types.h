/* wv_types.h — the flat structs + the shim_* callbacks (C++ host -> ...).
 * Included by BOTH the C++ shim and the nimony-generated C. It deliberately
 * does NOT declare the wv_* exports (those live in wv_exports.h, included only
 * by the shim) so the nimony-generated definitions never clash with a
 * differently-const-qualified prototype. */
#ifndef WV_TYPES_H_
#define WV_TYPES_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint32_t clear_bytes;
  uint32_t cipher_bytes;
} WvSubsample;

typedef struct {
  const uint8_t* data;
  uint32_t data_size;
  uint32_t encryption_scheme;
  const uint8_t* key_id;
  uint32_t key_id_size;
  const uint8_t* iv;
  uint32_t iv_size;
  const WvSubsample* subsamples;
  uint32_t num_subsamples;
  uint32_t crypt_byte_block;
  uint32_t skip_byte_block;
  int64_t timestamp;
} WvInputBuffer;

typedef struct {
  const uint8_t* key_id;
  uint32_t key_id_size;
  uint32_t status;
  uint32_t system_code;
} WvKeyInfo;

void* shim_host_allocate(void* host, uint32_t capacity);
uint8_t* shim_buf_data(void* buf);
uint32_t shim_buf_capacity(void* buf);
void shim_buf_set_size(void* buf, uint32_t n);
void shim_buf_destroy(void* buf);
void shim_block_set_buffer(void* block, void* buf);
void shim_block_set_timestamp(void* block, int64_t ts);

void shim_host_on_initialized(void* host, int success);
void shim_host_on_resolve_promise(void* host, uint32_t pid);
void shim_host_on_resolve_new_session(void* host, uint32_t pid,
                                      const char* sid, uint32_t n);
void shim_host_on_resolve_key_status(void* host, uint32_t pid, uint32_t key_status);
void shim_host_on_reject_promise(void* host, uint32_t pid, uint32_t exc,
                                 uint32_t system_code, const char* msg,
                                 uint32_t msg_len);
void shim_host_on_session_message(void* host, const char* sid, uint32_t n,
                                  uint32_t msg_type, const uint8_t* msg,
                                  uint32_t msg_len);
void shim_host_on_session_keys_change(void* host, const char* sid, uint32_t n,
                                      int has_new_key, const WvKeyInfo* keys,
                                      uint32_t count);
void shim_host_on_session_closed(void* host, const char* sid, uint32_t n);

#ifdef __cplusplus
}
#endif
#endif /* WV_TYPES_H_ */
