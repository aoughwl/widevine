## Session lifecycle and store (openwv's session.rs). The state machine:
##   AwaitingServiceCert -> AwaitingLicense -> Active

import wvcrypto, contentkey, wvd, servicecert, license, initdata, messages, config

type
  SessionStateKind* = enum
    ssAwaitingServiceCert, ssAwaitingLicense, ssActive, ssInvalid

  SessionEventKind* = enum
    seNone, seMessage, seKeysChange

  SessionEvent* = object
    kind*: SessionEventKind
    message*: seq[byte]     ## valid when kind == seMessage
    newKeys*: bool          ## valid when kind == seKeysChange

  Session* = object
    id*: string
    stateKind*: SessionStateKind
    contentId*: seq[byte]    ## held while AwaitingServiceCert
    requestBytes*: seq[byte] ## held while AwaitingLicense
    keys*: seq[ContentKey]

  SessionError* = enum
    serNone, serInitUnsupported, serInitBad, serServiceCert, serLicense,
    serInvalidState, serRequestFailed

const hexUpper = "0123456789ABCDEF"

proc generateSessionId(): string =
  let r = randomBytes(16)
  result = ""
  for b in r:
    result.add hexUpper[int(b shr 4)]
    result.add hexUpper[int(b and 0x0F'u8)]

proc noEvent(): SessionEvent =
  SessionEvent(kind: seNone, message: @[], newKeys: false)

proc msgEvent(m: seq[byte]): SessionEvent =
  SessionEvent(kind: seMessage, message: m, newKeys: false)

# --- create ----------------------------------------------------------------

proc createSession*(device: WidevineDevice, hasCert: bool, cert: ServerCertificate,
                    initDataType: uint32, initData: seq[byte],
                    outSession: var Session, outEvent: var SessionEvent,
                    err: var SessionError): bool =
  err = serNone
  outEvent = noEvent()

  # Honour the "never encrypt" policy by ignoring any stored certificate.
  var useCert = hasCert
  if encryptPolicy == eciNever:
    useCert = false

  let idr = initDataToContentId(initDataType, initData)
  if not idr.ok:
    err = if idr.unsupported: serInitUnsupported else: serInitBad
    return false

  var session = Session(id: generateSessionId(), stateKind: ssInvalid,
                        contentId: @[], requestBytes: @[], keys: @[])

  if encryptPolicy == eciAlways and not useCert:
    # Need a service certificate before we can encrypt the client id.
    session.stateKind = ssAwaitingServiceCert
    session.contentId = idr.contentId
    outEvent = msgEvent(encServiceCertificateRequest())
  else:
    var signedMsg: seq[byte] = @[]
    var requestBytes: seq[byte] = @[]
    if not requestLicense(idr.contentId, useCert, cert, device, signedMsg, requestBytes):
      err = serRequestFailed
      return false
    session.stateKind = ssAwaitingLicense
    session.requestBytes = requestBytes
    outEvent = msgEvent(signedMsg)

  outSession = session
  true

# --- update ----------------------------------------------------------------

proc updateSession*(session: var Session, device: WidevineDevice,
                    message: seq[byte], outEvent: var SessionEvent,
                    err: var SessionError): bool =
  err = serNone
  outEvent = noEvent()

  case session.stateKind
  of ssAwaitingServiceCert:
    var cert = ServerCertificate(publicKey: @[], serialNumber: @[], providerId: "")
    var sce = sceNone
    if not parseServiceCertMessage(message, cert, sce):
      session.stateKind = ssInvalid
      err = serServiceCert
      return false
    var signedMsg: seq[byte] = @[]
    var requestBytes: seq[byte] = @[]
    if not requestLicense(session.contentId, true, cert, device, signedMsg, requestBytes):
      session.stateKind = ssInvalid
      err = serRequestFailed
      return false
    session.stateKind = ssAwaitingLicense
    session.requestBytes = requestBytes
    outEvent = msgEvent(signedMsg)
    true
  of ssAwaitingLicense:
    var addedKeys = false
    var le = leNone
    if not loadLicenseKeys(message, session.requestBytes, device, session.keys,
                           addedKeys, le):
      session.stateKind = ssInvalid
      err = serLicense
      return false
    session.stateKind = ssActive
    if addedKeys:
      outEvent = SessionEvent(kind: seKeysChange, message: @[], newKeys: true)
    true
  else:
    err = serInvalidState
    false

proc clearLicenses*(session: var Session) =
  session.keys = @[]

# --- store (linear; sessions are few) --------------------------------------

type
  SessionStore* = object
    items*: seq[Session]

proc initSessionStore*(): SessionStore =
  SessionStore(items: @[])

proc indexOf*(store: SessionStore, id: string): int =
  for i in 0 ..< store.items.len:
    if store.items[i].id == id:
      return i
  -1

proc add*(store: var SessionStore, session: Session) =
  store.items.add session

proc deleteById*(store: var SessionStore, id: string) =
  let idx = store.indexOf(id)
  if idx >= 0:
    store.items.del idx

proc lookupKey*(store: SessionStore, keyId: seq[byte], found: var ContentKey): bool =
  for s in store.items:
    for k in s.keys:
      if k.hasId and k.id.len == keyId.len:
        var same = true
        for i in 0 ..< keyId.len:
          if k.id[i] != keyId[i]:
            same = false
            break
        if same:
          found = k
          return true
  false
