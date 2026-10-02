/* wv_exports.h — the wv_* functions exported by the nimony layer, declared
 * const-correctly for the C++ shim's call sites. Included ONLY by shim.cpp.
 * The nimony-generated C defines these (via exportc) without seeing this
 * header; C linkage matches them by name, so pointer const-qualifiers here are
 * invisible across the link. */
#ifndef WV_EXPORTS_H_
#define WV_EXPORTS_H_

#include <stdint.h>
#include "wv_types.h"

#ifdef __cplusplus
extern "C" {
#endif

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
int wv_decrypt(void* h, const WvInputBuffer* in, void* block);

#ifdef __cplusplus
}
#endif
#endif /* WV_EXPORTS_H_ */
