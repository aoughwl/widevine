/* wv_abi.h — the flat C ABI between the C++ shim and the nimony logic layer.
 *
 * `wv_*`   : exported by the nimony layer, called by shim.cpp.
 * `shim_*` : exported by shim.cpp, imported by the nimony layer (these reach
 *            back into the C++ cdm::Host_NN / Buffer / DecryptedBlock objects).
 *
 * Kept free of any C++ / cdm:: types so the nimony side can mirror it verbatim.
 */
#ifndef WV_ABI_H_
#define WV_ABI_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Flat mirror of cdm::SubsampleEntry. */
typedef struct {
  uint32_t clear_bytes;
  uint32_t cipher_bytes;
} WvSubsample;

/* Flat mirror of the parts of cdm::InputBuffer_2 we use. The shim fills this
 * from the real C++ struct so the nimony side never sees cdm:: types. */
typedef struct {
  const uint8_t* data;
  uint32_t data_size;
  uint32_t encryption_scheme; /* cdm::EncryptionScheme: 0 none,1 cenc,2 cbcs */
  const uint8_t* key_id;
  uint32_t key_id_size;
  const uint8_t* iv;
  uint32_t iv_size;
  const WvSubsample* subsamples;
  uint32_t num_subsamples;
  uint32_t crypt_byte_block; /* cdm::Pattern */
  uint32_t skip_byte_block;
  int64_t timestamp;
} WvInputBuffer;

/* Flat mirror of cdm::KeyInformation for OnSessionKeysChange. */
typedef struct {
  const uint8_t* key_id;
  uint32_t key_id_size;
  uint32_t status; /* cdm::KeyStatus */
  uint32_t system_code;
} WvKeyInfo;

/* ---- exported by nimony ---- */
void wv_initialize_module(void);
void wv_deinitialize_module(void);
const char* wv_get_version(void);
void* wv_create(void* host, int iface_version);
void wv_destroy(void* h);

void wv_initialize(void* h, int allow_distinct, int allow_persist, int hw_secure);
void wv_get_status_for_policy(void* h, uint32_t promise_id);
void wv_set_server_certificate(void* h, uint32_t promise_id,
                               const uint8_t* data, uint32_t size);
void wv_create_session(void* h, uint32_t promise_id, uint32_t session_type,
                       uint32_t init_data_type, const uint8_t* init_data,
                       uint32_t size);
void wv_load_session(void* h, uint32_t promise_id, uint32_t session_type,
                     const char* sid, uint32_t sid_size);
void wv_update_session(void* h, uint32_t promise_id, const char* sid,
                       uint32_t sid_size, const uint8_t* resp, uint32_t resp_size);
void wv_close_session(void* h, uint32_t promise_id, const char* sid,
                      uint32_t sid_size);
void wv_remove_session(void* h, uint32_t promise_id, const char* sid,
                       uint32_t sid_size);
/* returns a cdm::Status (0 success, 2 no key, 4 decrypt error). The handle
 * stores its host (from wv_create), so decrypt needs only the block. */
int wv_decrypt(void* h, const WvInputBuffer* in, void* block);

/* ---- exported by shim.cpp (call into the C++ host) ---- */
void* shim_host_allocate(void* host, uint32_t capacity); /* cdm::Buffer* */
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
                                  uint32_t msg_type, const char* msg,
                                  uint32_t msg_len);
void shim_host_on_session_keys_change(void* host, const char* sid, uint32_t n,
                                      int has_new_key, const WvKeyInfo* keys,
                                      uint32_t count);
void shim_host_on_session_closed(void* host, const char* sid, uint32_t n);

#ifdef __cplusplus
}
#endif
#endif /* WV_ABI_H_ */
