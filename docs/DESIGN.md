# Design

A straight port of [openwv](https://github.com/tchebb/openwv)'s design to
nimony. Where openwv uses `autocxx` to subclass the C++ CDM interface and
RustCrypto for crypto, this port uses a hand-written C++ shim and mbedTLS,
because nimony has neither C++ class-subclassing interop nor a crypto library.

## Layers and the C ABI between them

Three object files are linked into one shared library:

1. nimony-generated C (from `src/*.nim`)
2. `cpp/shim.cpp` (C++)
3. `cpp/wvcrypto.c` (C) + `libmbedcrypto.a`

### shim.cpp ⟷ nimony  (the `wv_*` ABI)

The CDM instance's state lives on the nimony side as an opaque handle
(`void*`). The shim owns a C++ object whose vtable methods each forward to a
`wv_*` C function.

Exported by nimony, called by the shim:

```
void  wv_initialize_module(void);
void  wv_deinitialize_module(void);
const char* wv_get_version(void);
void* wv_create(void* host, int iface_version);   // returns handle or NULL
void  wv_destroy(void* h);

void  wv_initialize(void* h, int allow_distinct, int allow_persist, int hw_secure);
void  wv_get_status_for_policy(void* h, uint32_t promise_id);
void  wv_set_server_certificate(void* h, uint32_t promise_id,
                                const uint8_t* data, uint32_t size);
void  wv_create_session(void* h, uint32_t promise_id, uint32_t session_type,
                        uint32_t init_data_type, const uint8_t* init_data, uint32_t size);
void  wv_load_session(void* h, uint32_t promise_id, uint32_t session_type,
                      const char* sid, uint32_t sid_size);
void  wv_update_session(void* h, uint32_t promise_id, const char* sid, uint32_t sid_size,
                        const uint8_t* resp, uint32_t resp_size);
void  wv_close_session(void* h, uint32_t promise_id, const char* sid, uint32_t sid_size);
void  wv_remove_session(void* h, uint32_t promise_id, const char* sid, uint32_t sid_size);

// Decrypt: the shim passes the InputBuffer_2 fields plus the host (for
// Allocate) and the DecryptedBlock (for the result). nimony calls back into
// shim_buf_* / shim_block_* to produce output. Returns a cdm::Status.
int   wv_decrypt(void* h, const WvInputBuffer* in, void* host, void* decrypted_block);
```

`WvInputBuffer` is a flat C mirror of `cdm::InputBuffer_2` (and its subsample /
pattern arrays) that the shim fills in — nimony never sees the real C++ struct.

Imported by nimony, implemented in the shim (these call the C++ `Host_10/11`
vtable and the `Buffer`/`DecryptedBlock` interfaces — safe to always cast the
host to `Host_10*` because every method we use sits at an identical vtable slot
in both versions; `Host_11` only appends `ReportMetrics`):

```
void* shim_host_allocate(void* host, uint32_t capacity);        // -> cdm::Buffer*
uint8_t* shim_buf_data(void* buf);
void  shim_buf_set_size(void* buf, uint32_t n);
void  shim_buf_destroy(void* buf);
void  shim_block_set_buffer(void* block, void* buf);
void  shim_block_set_timestamp(void* block, int64_t ts);

void  shim_host_on_initialized(void* host, int success);
void  shim_host_on_resolve_promise(void* host, uint32_t pid);
void  shim_host_on_resolve_new_session(void* host, uint32_t pid, const char* sid, uint32_t n);
void  shim_host_on_resolve_key_status(void* host, uint32_t pid, uint32_t key_status);
void  shim_host_on_reject_promise(void* host, uint32_t pid, uint32_t exc,
                                  uint32_t system_code, const char* msg, uint32_t msg_len);
void  shim_host_on_session_message(void* host, const char* sid, uint32_t n,
                                   uint32_t msg_type, const char* msg, uint32_t msg_len);
void  shim_host_on_session_keys_change(void* host, const char* sid, uint32_t n,
                                       int has_new_key, const WvKeyInfo* keys, uint32_t count);
void  shim_host_on_session_closed(void* host, const char* sid, uint32_t n);
```

### wvcrypto.c ⟷ nimony  (the `wvc_*` ABI)

Flat, allocation-free where possible. All return `0` on success, non-zero on
error. See `cpp/wvcrypto.h` for the authoritative list. Primitives: `wvc_sha1`,
`wvc_sha256`, `wvc_hmac_sha256`, `wvc_aes128_cmac`, `wvc_aes128_ctr`,
`wvc_aes128_cbc_decrypt`, `wvc_aes128_cbc_decrypt_pkcs7`,
`wvc_aes128_cbc_encrypt_pkcs7`, `wvc_rsa_pss_sha1_sign`,
`wvc_rsa_pss_sha1_verify`, `wvc_rsa_oaep_sha1_decrypt`,
`wvc_rsa_oaep_sha1_encrypt`, `wvc_random`.

## nimony module map (`src/`)

| module          | openwv counterpart        | responsibility |
|-----------------|---------------------------|----------------|
| `widevine.nim`  | `lib.rs` + `openwv.rs`     | `wv_*` exports; CDM instance struct; dispatch |
| `config.nim`    | `config.rs`               | compile-time config; embeds `embedded.wvd` |
| `util.nim`      | `util.rs`                 | time, hex, small helpers |
| `cdmtypes.nim`  | the `ffi::cdm` enums      | enum/const mirrors of the CDM ABI |
| `wvcrypto.nim`  | (RustCrypto)              | `importc` bindings to `wvc_*` + ergonomic wrappers |
| `proto.nim`     | (prost runtime)           | minimal protobuf wire codec |
| `messages.nim`  | generated protobuf        | the Widevine message structs + encode/decode |
| `wvd.nim`       | `wvd_file.rs`             | parse the embedded device |
| `initdata.nim`  | `init_data.rs`            | PSSH / CENC init-data → ContentIdentification |
| `signedmsg.nim` | `signed_message.rs`       | SignedMessage encapsulation + signature checks |
| `servicecert.nim`| `service_certificate.rs` | parse/verify service cert; encrypt client id |
| `license.nim`   | `license.rs`              | build request; load keys; KDF |
| `contentkey.nim`| `content_key.rs`          | the decrypted content-key record |
| `session.nim`   | `session.rs`              | session id, state machine, session store |
| `decrypt.nim`   | `decrypt.rs`              | CENC/CBCS subsample+pattern decrypt |

## State machine (per session)

`AwaitingServiceCert → AwaitingLicense → Active`, exactly as openwv:

- `create`: parse init data → ContentIdentification. If policy says encrypt the
  client id and no service cert is known, emit a `ServiceCertificateRequest`
  and park in `AwaitingServiceCert`. Otherwise build+sign the license request,
  emit it, park in `AwaitingLicense`.
- `update` while `AwaitingServiceCert`: parse the service cert from the
  message, build the (now client-id-encrypting) license request, emit it, move
  to `AwaitingLicense`.
- `update` while `AwaitingLicense`: verify HMAC, decrypt keys, store them, fire
  a keys-change event, move to `Active`.

## Memory & safety notes

- The nimony handle is heap-allocated in `wv_create` and freed in `wv_destroy`
  (`Destroy()` on the C++ side). The C++ object owns the handle.
- Buffers crossing the ABI are (ptr,len) pairs; nimony copies into its own
  `seq[byte]` before doing anything that could reallocate.
- `panic:abort` semantics: a nimony panic must not unwind into C++. Entry
  points catch/guard where the language allows and otherwise abort, matching
  openwv's `panic = "abort"`.
