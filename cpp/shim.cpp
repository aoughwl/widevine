/* shim.cpp — the C++ boundary of the CDM.
 *
 * Provides the exported library entry points, subclasses the Widevine CDM
 * interface (cdm::CommonCdm, which derives from both ContentDecryptionModule_10
 * and _11), and exposes the host callbacks as the flat `shim_*` C functions the
 * nimony logic layer calls. All real logic lives on the nimony side behind the
 * opaque `void* handle`.
 *
 * This mirrors what openwv gets from autocxx's `subclass!`, done by hand. */
#include "common_cdm.h"
#include "wv_abi.h"

#include <cstring>
#include <new>

using namespace cdm;

/* The host vtables for versions 10 and 11 are identical for every method we
 * call (Host_11 only appends ReportMetrics), so a single Host_10* cast is ABI
 * correct regardless of the negotiated version. */
static inline Host_10* H(void* host) { return static_cast<Host_10*>(host); }

/* ===================================================================== *
 *  shim_* : nimony -> C++ host / buffers                                *
 * ===================================================================== */
extern "C" {

void* shim_host_allocate(void* host, uint32_t capacity) {
  return H(host)->Allocate(capacity);
}
uint8_t* shim_buf_data(void* buf) { return static_cast<Buffer*>(buf)->Data(); }
uint32_t shim_buf_capacity(void* buf) {
  return static_cast<Buffer*>(buf)->Capacity();
}
void shim_buf_set_size(void* buf, uint32_t n) {
  static_cast<Buffer*>(buf)->SetSize(n);
}
void shim_buf_destroy(void* buf) { static_cast<Buffer*>(buf)->Destroy(); }
void shim_block_set_buffer(void* block, void* buf) {
  static_cast<DecryptedBlock*>(block)->SetDecryptedBuffer(
      static_cast<Buffer*>(buf));
}
void shim_block_set_timestamp(void* block, int64_t ts) {
  static_cast<DecryptedBlock*>(block)->SetTimestamp(ts);
}

void shim_host_on_initialized(void* host, int success) {
  H(host)->OnInitialized(success != 0);
}
void shim_host_on_resolve_promise(void* host, uint32_t pid) {
  H(host)->OnResolvePromise(pid);
}
void shim_host_on_resolve_new_session(void* host, uint32_t pid,
                                      const char* sid, uint32_t n) {
  H(host)->OnResolveNewSessionPromise(pid, sid, n);
}
void shim_host_on_resolve_key_status(void* host, uint32_t pid,
                                     uint32_t key_status) {
  H(host)->OnResolveKeyStatusPromise(pid, static_cast<KeyStatus>(key_status));
}
void shim_host_on_reject_promise(void* host, uint32_t pid, uint32_t exc,
                                 uint32_t system_code, const char* msg,
                                 uint32_t msg_len) {
  H(host)->OnRejectPromise(pid, static_cast<Exception>(exc), system_code, msg,
                           msg_len);
}
void shim_host_on_session_message(void* host, const char* sid, uint32_t n,
                                  uint32_t msg_type, const char* msg,
                                  uint32_t msg_len) {
  H(host)->OnSessionMessage(sid, n, static_cast<MessageType>(msg_type), msg,
                            msg_len);
}
void shim_host_on_session_keys_change(void* host, const char* sid, uint32_t n,
                                      int has_new_key, const WvKeyInfo* keys,
                                      uint32_t count) {
  /* WvKeyInfo is layout-compatible with cdm::KeyInformation. */
  H(host)->OnSessionKeysChange(sid, n, has_new_key != 0,
                               reinterpret_cast<const KeyInformation*>(keys),
                               count);
}
void shim_host_on_session_closed(void* host, const char* sid, uint32_t n) {
  H(host)->OnSessionClosed(sid, n);
}

}  // extern "C"

/* ===================================================================== *
 *  The CDM subclass: C++ vtable -> nimony wv_*                           *
 * ===================================================================== */
namespace {

class OpenWvCdm : public CommonCdm {
 public:
  explicit OpenWvCdm(void* handle) : handle_(handle) {}

  void Initialize(bool allow_distinctive_identifier, bool allow_persistent_state,
                  bool use_hw_secure_codecs) override {
    wv_initialize(handle_, allow_distinctive_identifier, allow_persistent_state,
                  use_hw_secure_codecs);
  }
  void GetStatusForPolicy(uint32_t promise_id, const Policy&) override {
    wv_get_status_for_policy(handle_, promise_id);
  }
  void SetServerCertificate(uint32_t promise_id, const uint8_t* data,
                            uint32_t size) override {
    wv_set_server_certificate(handle_, promise_id, data, size);
  }
  void CreateSessionAndGenerateRequest(uint32_t promise_id,
                                       SessionType session_type,
                                       InitDataType init_data_type,
                                       const uint8_t* init_data,
                                       uint32_t init_data_size) override {
    wv_create_session(handle_, promise_id, session_type, init_data_type,
                      init_data, init_data_size);
  }
  void LoadSession(uint32_t promise_id, SessionType session_type,
                   const char* session_id, uint32_t session_id_size) override {
    wv_load_session(handle_, promise_id, session_type, session_id,
                    session_id_size);
  }
  void UpdateSession(uint32_t promise_id, const char* session_id,
                     uint32_t session_id_size, const uint8_t* response,
                     uint32_t response_size) override {
    wv_update_session(handle_, promise_id, session_id, session_id_size, response,
                      response_size);
  }
  void CloseSession(uint32_t promise_id, const char* session_id,
                    uint32_t session_id_size) override {
    wv_close_session(handle_, promise_id, session_id, session_id_size);
  }
  void RemoveSession(uint32_t promise_id, const char* session_id,
                     uint32_t session_id_size) override {
    wv_remove_session(handle_, promise_id, session_id, session_id_size);
  }
  void TimerExpired(void*) override {}

  Status Decrypt(const InputBuffer_2& in, DecryptedBlock* out) override {
    WvInputBuffer w;
    std::memset(&w, 0, sizeof(w));
    w.data = in.data;
    w.data_size = in.data_size;
    w.encryption_scheme = static_cast<uint32_t>(in.encryption_scheme);
    w.key_id = in.key_id;
    w.key_id_size = in.key_id_size;
    w.iv = in.iv;
    w.iv_size = in.iv_size;
    w.subsamples = reinterpret_cast<const WvSubsample*>(in.subsamples);
    w.num_subsamples = in.num_subsamples;
    w.crypt_byte_block = in.pattern.crypt_byte_block;
    w.skip_byte_block = in.pattern.skip_byte_block;
    w.timestamp = in.timestamp;
    return static_cast<Status>(wv_decrypt(handle_, &w, out));
  }

  Status InitializeAudioDecoder(const AudioDecoderConfig_2&) override {
    return kInitializationError;
  }
  Status InitializeVideoDecoder(const VideoDecoderConfig_2&) override {
    return kInitializationError;
  }
  void DeinitializeDecoder(StreamType) override {}
  void ResetDecoder(StreamType) override {}
  Status DecryptAndDecodeFrame(const InputBuffer_2&, VideoFrame*) override {
    return kDecodeError;
  }
  Status DecryptAndDecodeSamples(const InputBuffer_2&, AudioFrames*) override {
    return kDecodeError;
  }
  void OnPlatformChallengeResponse(const PlatformChallengeResponse&) override {}
  void OnQueryOutputProtectionStatus(QueryResult, uint32_t, uint32_t) override {}
  void OnStorageId(uint32_t, const uint8_t*, uint32_t) override {}

  void Destroy() override {
    wv_destroy(handle_);
    delete this;
  }

 private:
  void* handle_;
};

}  // namespace

/* ===================================================================== *
 *  Exported library entry points                                        *
 * ===================================================================== */
#if defined(_WIN32)
#define WV_EXPORT extern "C" __declspec(dllexport)
#else
#define WV_EXPORT extern "C" __attribute__((visibility("default")))
#endif

WV_EXPORT void InitializeCdmModule_4() { wv_initialize_module(); }
WV_EXPORT void DeinitializeCdmModule() { wv_deinitialize_module(); }
WV_EXPORT const char* GetCdmVersion() { return wv_get_version(); }

typedef void* (*GetCdmHostFunc)(int host_interface_version, void* user_data);

static const char kWidevineKeySystem[] = "com.widevine.alpha";

WV_EXPORT void* CreateCdmInstance(int cdm_interface_version,
                                  const char* key_system,
                                  uint32_t key_system_size,
                                  GetCdmHostFunc get_cdm_host_func,
                                  void* user_data) {
  if (cdm_interface_version != 10 && cdm_interface_version != 11) return nullptr;
  if (!key_system ||
      key_system_size != (sizeof(kWidevineKeySystem) - 1) ||
      std::memcmp(key_system, kWidevineKeySystem, key_system_size) != 0) {
    return nullptr;
  }
  if (!get_cdm_host_func) return nullptr;
  void* host = get_cdm_host_func(cdm_interface_version, user_data);
  if (!host) return nullptr;

  void* handle = wv_create(host, cdm_interface_version);
  if (!handle) return nullptr;

  OpenWvCdm* cdm = new (std::nothrow) OpenWvCdm(handle);
  if (!cdm) {
    wv_destroy(handle);
    return nullptr;
  }
  /* Return the pointer cast to the requested interface. */
  if (cdm_interface_version == 10)
    return static_cast<ContentDecryptionModule_10*>(cdm);
  return static_cast<ContentDecryptionModule_11*>(cdm);
}
