## OpenWV-nimony main module: the `wv_*` C ABI the C++ shim calls, the CDM
## instance, and the dispatch that drives the session machine and host
## callbacks. Compiled with `--app:lib` into widevinecdm.dll.
##
## Build injection: pull the C++ shim and the mbedTLS crypto wrapper into the
## link, plus the mbedTLS static lib (paths are relative to this file / a
## src/-cwd build; see tools/build).

{.passC: "-I../cpp".}
{.compile("../cpp/shim.cpp", "-I../cpp -I../third-party/cdm -fno-exceptions -fno-rtti").}
{.compile("../cpp/wvcrypto.c", "-I../cpp -I../third-party/mbedtls/include").}
{.passL: "-static -L../third-party/mbedtls/library -lmbedcrypto -lbcrypt".}

import config, cdmtypes, wvd, servicecert, session, contentkey, decrypt

# ===========================================================================
# shim.cpp imports (reach into the C++ host / buffers)
# ===========================================================================

type
  WvSubsampleC {.importc: "WvSubsample", header: "wv_types.h".} = object
    clear_bytes: uint32
    cipher_bytes: uint32

  WvInputBufferC {.importc: "WvInputBuffer", header: "wv_types.h".} = object
    data: ptr byte
    data_size: uint32
    encryption_scheme: uint32
    key_id: ptr byte
    key_id_size: uint32
    iv: ptr byte
    iv_size: uint32
    subsamples: ptr WvSubsampleC
    num_subsamples: uint32
    crypt_byte_block: uint32
    skip_byte_block: uint32
    timestamp: int64

  WvKeyInfoC {.importc: "WvKeyInfo", header: "wv_types.h".} = object
    key_id: ptr byte
    key_id_size: uint32
    status: uint32
    system_code: uint32

proc shim_host_allocate(host: pointer, capacity: uint32): pointer {.importc, header: "wv_types.h".}
proc shim_buf_data(buf: pointer): ptr byte {.importc, header: "wv_types.h".}
proc shim_buf_set_size(buf: pointer, n: uint32) {.importc, header: "wv_types.h".}
proc shim_buf_destroy(buf: pointer) {.importc, header: "wv_types.h".}
proc shim_block_set_buffer(blk: pointer, buf: pointer) {.importc, header: "wv_types.h".}
proc shim_block_set_timestamp(blk: pointer, ts: int64) {.importc, header: "wv_types.h".}

proc shim_host_on_initialized(host: pointer, success: cint) {.importc, header: "wv_types.h".}
proc shim_host_on_resolve_promise(host: pointer, pid: uint32) {.importc, header: "wv_types.h".}
proc shim_host_on_resolve_new_session(host: pointer, pid: uint32, sid: cstring, n: uint32) {.importc, header: "wv_types.h".}
proc shim_host_on_resolve_key_status(host: pointer, pid: uint32, keyStatus: uint32) {.importc, header: "wv_types.h".}
proc shim_host_on_reject_promise(host: pointer, pid: uint32, exc: uint32, systemCode: uint32, msg: cstring, msgLen: uint32) {.importc, header: "wv_types.h".}
proc shim_host_on_session_message(host: pointer, sid: cstring, n: uint32, msgType: uint32, msg: ptr byte, msgLen: uint32) {.importc, header: "wv_types.h".}
proc shim_host_on_session_keys_change(host: pointer, sid: cstring, n: uint32, hasNewKey: cint, keys: ptr WvKeyInfoC, count: uint32) {.importc, header: "wv_types.h".}
proc shim_host_on_session_closed(host: pointer, sid: cstring, n: uint32) {.importc, header: "wv_types.h".}

# ===========================================================================
# CDM instance + module-global device
# ===========================================================================

type
  CdmInstance = object
    alive: bool
    host: pointer
    store: SessionStore
    hasCert: bool
    cert: ServerCertificate
    allowPersistentState: bool

var gInstances: seq[CdmInstance] = @[]
var gDevice: WidevineDevice = WidevineDevice(privateKey: @[], clientId: @[])
var gDeviceOk: bool = false

proc inst(h: pointer): int =
  ## Decode a handle to a live instance index, or -1.
  let idx = cast[int](h) - 1
  if idx < 0 or idx >= gInstances.len or not gInstances[idx].alive:
    return -1
  idx

# ===========================================================================
# small pointer/buffer helpers
# ===========================================================================

proc ptrToSeq(p: ptr byte, n: uint32): seq[byte] =
  result = @[]
  if cast[int](p) == 0 or n == 0'u32:
    return
  let arr = cast[ptr UncheckedArray[byte]](p)
  for i in 0 ..< int(n):
    result.add arr[i]

proc rejectExc(host: pointer, pid: uint32, exc: uint32, message: string) =
  var m = message
  shim_host_on_reject_promise(host, pid, exc, 0'u32, toCString(m),
                              uint32(m.len))

# ===========================================================================
# event delivery
# ===========================================================================

proc deliverEvent(host: pointer, session: Session, ev: SessionEvent) =
  var sid = session.id
  case ev.kind
  of seNone:
    discard
  of seMessage:
    var msg = ev.message
    let mp = if msg.len == 0: cast[ptr byte](0) else: addr msg[0]
    shim_host_on_session_message(host, toCString(sid),
                                 uint32(sid.len), mtLicenseRequest,
                                 mp, uint32(msg.len))
  of seKeysChange:
    # Build KeyInformation entries pointing into the session's key ids.
    var infos: seq[WvKeyInfoC] = @[]
    for k in session.keys:
      if k.hasId and k.id.len > 0:
        infos.add WvKeyInfoC(key_id: addr k.id[0], key_id_size: uint32(k.id.len),
                             status: ksUsable, system_code: 0'u32)
    let ip = if infos.len == 0: cast[ptr WvKeyInfoC](0) else: addr infos[0]
    shim_host_on_session_keys_change(host, toCString(sid),
                                     uint32(sid.len), cint(1), ip,
                                     uint32(infos.len))

# ===========================================================================
# exported wv_* ABI
# ===========================================================================

proc wv_initialize_module() {.exportc: "wv_initialize_module".} =
  var dev = WidevineDevice(privateKey: @[], clientId: @[])
  if parseWvd(widevineDeviceBytes(), dev):
    gDevice = dev
    gDeviceOk = true
  else:
    gDeviceOk = false

proc wv_deinitialize_module() {.exportc: "wv_deinitialize_module".} =
  discard

proc wv_get_version(): cstring {.exportc: "wv_get_version".} =
  cstring("OpenWV-nimony 0.1.0")

proc wv_create(host: pointer, ifaceVersion: cint): pointer {.exportc: "wv_create".} =
  if not gDeviceOk:
    return cast[pointer](0)
  gInstances.add CdmInstance(alive: true, host: host, store: initSessionStore(),
                             hasCert: false,
                             cert: ServerCertificate(publicKey: @[], serialNumber: @[], providerId: ""),
                             allowPersistentState: false)
  cast[pointer](gInstances.len)   # handle = index + 1

proc wv_destroy(h: pointer) {.exportc: "wv_destroy".} =
  let i = inst(h)
  if i >= 0:
    gInstances[i].alive = false
    gInstances[i].store = initSessionStore()

proc wv_initialize(h: pointer, allowDistinct: cint, allowPersist: cint, hwSecure: cint) {.exportc: "wv_initialize".} =
  let i = inst(h)
  if i < 0: return
  gInstances[i].allowPersistentState = allowPersist != 0
  shim_host_on_initialized(gInstances[i].host, cint(1))

proc wv_get_status_for_policy(h: pointer, pid: uint32) {.exportc: "wv_get_status_for_policy".} =
  let i = inst(h)
  if i < 0: return
  shim_host_on_resolve_key_status(gInstances[i].host, pid, ksUsable)

proc wv_set_server_certificate(h: pointer, pid: uint32, data: ptr byte, size: uint32) {.exportc: "wv_set_server_certificate".} =
  let i = inst(h)
  if i < 0: return
  let host = gInstances[i].host
  let certBytes = ptrToSeq(data, size)
  var cert = ServerCertificate(publicKey: @[], serialNumber: @[], providerId: "")
  var err = sceNone
  if parseServiceCertificate(certBytes, cert, err):
    gInstances[i].cert = cert
    gInstances[i].hasCert = true
    shim_host_on_resolve_promise(host, pid)
  else:
    let exc = if err == sceEmpty: excTypeError else: excInvalidStateError
    rejectExc(host, pid, exc, "invalid service certificate")

proc wv_create_session(h: pointer, pid: uint32, sessionType: uint32, initDataType: uint32, initData: ptr byte, size: uint32) {.exportc: "wv_create_session".} =
  let i = inst(h)
  if i < 0: return
  let host = gInstances[i].host
  if sessionType == sessPersistentLicense and not gInstances[i].allowPersistentState:
    rejectExc(host, pid, excNotSupportedError, "persistent state not allowed")
    return

  let initBytes = ptrToSeq(initData, size)
  var session = Session(id: "", stateKind: ssInvalid, contentId: @[], requestBytes: @[], keys: @[])
  var ev = SessionEvent(kind: seNone, message: @[], newKeys: false)
  var serr = serNone
  if createSession(gDevice, gInstances[i].hasCert, gInstances[i].cert,
                   initDataType, initBytes, session, ev, serr):
    var sidv = session.id
    shim_host_on_resolve_new_session(host, pid, toCString(sidv), uint32(sidv.len))
    deliverEvent(host, session, ev)
    gInstances[i].store.add session
  else:
    let exc = if serr == serInitUnsupported: excNotSupportedError else: excTypeError
    rejectExc(host, pid, exc, "could not create session")

proc wv_load_session(h: pointer, pid: uint32, sessionType: uint32, sid: cstring, sidSize: uint32) {.exportc: "wv_load_session".} =
  let i = inst(h)
  if i < 0: return
  rejectExc(gInstances[i].host, pid, excNotSupportedError, "no persistent sessions")

proc sidToString(sid: cstring, n: uint32): string =
  result = ""
  let arr = cast[ptr UncheckedArray[char]](sid)
  for j in 0 ..< int(n):
    result.add arr[j]

proc wv_update_session(h: pointer, pid: uint32, sid: cstring, sidSize: uint32, resp: ptr byte, respSize: uint32) {.exportc: "wv_update_session".} =
  let i = inst(h)
  if i < 0: return
  let host = gInstances[i].host
  let id = sidToString(sid, sidSize)
  let idx = gInstances[i].store.indexOf(id)
  if idx < 0:
    rejectExc(host, pid, excInvalidStateError, "invalid session id")
    return
  let message = ptrToSeq(resp, respSize)
  var ev = SessionEvent(kind: seNone, message: @[], newKeys: false)
  var serr = serNone
  if updateSession(gInstances[i].store.items[idx], gDevice, message, ev, serr):
    # Resolve first, then deliver the key-change event (matches Google's CDM).
    shim_host_on_resolve_promise(host, pid)
    deliverEvent(host, gInstances[i].store.items[idx], ev)
  else:
    rejectExc(host, pid, excTypeError, "session update failed")

proc wv_close_session(h: pointer, pid: uint32, sid: cstring, sidSize: uint32) {.exportc: "wv_close_session".} =
  let i = inst(h)
  if i < 0: return
  let host = gInstances[i].host
  let id = sidToString(sid, sidSize)
  if gInstances[i].store.indexOf(id) < 0:
    rejectExc(host, pid, excInvalidStateError, "invalid session id")
    return
  gInstances[i].store.deleteById(id)
  shim_host_on_resolve_promise(host, pid)
  var idv = id
  shim_host_on_session_closed(host, toCString(idv), uint32(idv.len))

proc wv_remove_session(h: pointer, pid: uint32, sid: cstring, sidSize: uint32) {.exportc: "wv_remove_session".} =
  let i = inst(h)
  if i < 0: return
  let host = gInstances[i].host
  let id = sidToString(sid, sidSize)
  let idx = gInstances[i].store.indexOf(id)
  if idx < 0:
    rejectExc(host, pid, excInvalidStateError, "invalid session id")
    return
  clearLicenses(gInstances[i].store.items[idx])
  shim_host_on_resolve_promise(host, pid)

proc wv_decrypt(h: pointer, inp: ptr WvInputBufferC, blk: pointer): cint {.exportc: "wv_decrypt".} =
  let i = inst(h)
  if i < 0: return stDecryptError
  if cast[int](inp) == 0: return stSuccess
  let ib = cast[ptr WvInputBufferC](inp)

  var data = ptrToSeq(ib.data, ib.data_size)
  let keyId = ptrToSeq(ib.key_id, ib.key_id_size)
  let iv = ptrToSeq(ib.iv, ib.iv_size)

  var subs: seq[Subsample] = @[]
  if ib.num_subsamples > 0'u32 and cast[int](ib.subsamples) != 0:
    let sa = cast[ptr UncheckedArray[WvSubsampleC]](ib.subsamples)
    for s in 0 ..< int(ib.num_subsamples):
      subs.add Subsample(clear: int(sa[s].clear_bytes), cipher: int(sa[s].cipher_bytes))

  var key = ContentKey(id: @[], hasId: false, data: @[], keyType: -1, trackLabel: "")
  let hasKey = gInstances[i].store.lookupKey(keyId, key)
  let hasIv = iv.len > 0

  let st = decryptBuf(hasKey, key, hasIv, iv, data, ib.encryption_scheme, subs,
                      int(ib.crypt_byte_block), int(ib.skip_byte_block))
  case st
  of dsNoKey:
    return stNoKey
  of dsError:
    return stDecryptError
  of dsOk:
    let buf = shim_host_allocate(gInstances[i].host, ib.data_size)
    if cast[int](buf) == 0: return stDecryptError
    if data.len > 0:
      let dst = cast[ptr UncheckedArray[byte]](shim_buf_data(buf))
      for j in 0 ..< data.len:
        dst[j] = data[j]
    shim_buf_set_size(buf, ib.data_size)
    shim_block_set_buffer(blk, buf)
    shim_block_set_timestamp(blk, ib.timestamp)
    return stSuccess

# ===========================================================================
# anti-DCE anchors (nimony drops uncalled top-level procs otherwise)
# ===========================================================================

let a0 {.used.} = wv_initialize_module
let a1 {.used.} = wv_deinitialize_module
let a2 {.used.} = wv_get_version
let a3 {.used.} = wv_create
let a4 {.used.} = wv_destroy
let a5 {.used.} = wv_initialize
let a6 {.used.} = wv_get_status_for_policy
let a7 {.used.} = wv_set_server_certificate
let a8 {.used.} = wv_create_session
let a9 {.used.} = wv_load_session
let a10 {.used.} = wv_update_session
let a11 {.used.} = wv_close_session
let a12 {.used.} = wv_remove_session
let a13 {.used.} = wv_decrypt
