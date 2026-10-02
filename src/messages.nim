## Typed Widevine protobuf messages — the subset the CDM needs, built on the
## tiny codec in proto.nim. Field numbers come from docs/PROTO.md (canonical
## pywidevine license_protocol.proto). ClientIdentification is handled as opaque
## bytes (it is pre-serialized in the .wvd and only ever re-embedded/encrypted).

import proto

# --- enum constants --------------------------------------------------------

# SignedMessage.MessageType
const
  smLicenseRequest* = 1
  smLicense* = 2
  smErrorResponse* = 3
  smServiceCertificateRequest* = 4
  smServiceCertificate* = 5

# LicenseRequest.RequestType
const rtNew* = 1

# ProtocolVersion
const pvVersion21* = 21

# LicenseType
const ltStreaming* = 1

# License.KeyContainer.KeyType
const
  ktSigning* = 1
  ktContent* = 2

# DrmDeviceCertificate.CertificateType
const certTypeService* = 3

# ===========================================================================
# Encoders (request path)
# ===========================================================================

proc encWidevinePsshData*(psshData: seq[byte], requestId: seq[byte]): seq[byte] =
  var w = ProtoWriter(buf: @[])
  w.putBytes(1, psshData)           # pssh_data (repeated; single entry)
  w.putVarint(2, uint64(ltStreaming))
  w.putBytes(3, requestId)
  w.finish()

proc encWebmKeyId*(header: seq[byte], requestId: seq[byte]): seq[byte] =
  var w = ProtoWriter(buf: @[])
  w.putBytes(1, header)
  w.putVarint(2, uint64(ltStreaming))
  w.putBytes(3, requestId)
  w.finish()

proc encContentIdCenc*(psshData: seq[byte], requestId: seq[byte]): seq[byte] =
  ## ContentIdentification with widevine_pssh_data (field 1).
  var w = ProtoWriter(buf: @[])
  w.putBytes(1, encWidevinePsshData(psshData, requestId))
  w.finish()

proc encContentIdWebm*(header: seq[byte], requestId: seq[byte]): seq[byte] =
  ## ContentIdentification with webm_key_id (field 2).
  var w = ProtoWriter(buf: @[])
  w.putBytes(2, encWebmKeyId(header, requestId))
  w.finish()

proc encEncryptedClientId*(providerId: string, serial: seq[byte],
                           encClientId: seq[byte], iv: seq[byte],
                           encPrivacyKey: seq[byte]): seq[byte] =
  var w = ProtoWriter(buf: @[])
  w.putString(1, providerId)
  w.putBytes(2, serial)
  w.putBytes(3, encClientId)
  w.putBytes(4, iv)
  w.putBytes(5, encPrivacyKey)
  w.finish()

proc encLicenseRequestPlain*(contentId: seq[byte], clientId: seq[byte],
                             requestTime: int64, keyControlNonce: uint32): seq[byte] =
  ## LicenseRequest carrying a plaintext ClientIdentification (client_id = 1).
  var w = ProtoWriter(buf: @[])
  w.putBytes(1, clientId)
  w.putBytes(2, contentId)
  w.putVarint(3, uint64(rtNew))
  w.putVarint(4, uint64(requestTime))
  w.putVarint(6, uint64(pvVersion21))
  w.putVarint(7, uint64(keyControlNonce))
  w.finish()

proc encLicenseRequestEncrypted*(contentId: seq[byte], encryptedClientId: seq[byte],
                                 requestTime: int64, keyControlNonce: uint32): seq[byte] =
  ## LicenseRequest carrying an EncryptedClientIdentification (field 8).
  var w = ProtoWriter(buf: @[])
  w.putBytes(2, contentId)
  w.putVarint(3, uint64(rtNew))
  w.putVarint(4, uint64(requestTime))
  w.putVarint(6, uint64(pvVersion21))
  w.putVarint(7, uint64(keyControlNonce))
  w.putBytes(8, encryptedClientId)
  w.finish()

proc encSignedMessage*(msgType: int, msg: seq[byte], signature: seq[byte]): seq[byte] =
  var w = ProtoWriter(buf: @[])
  w.putVarint(1, uint64(msgType))
  if msg.len > 0:
    w.putBytes(2, msg)
  if signature.len > 0:
    w.putBytes(3, signature)
  w.finish()

proc encServiceCertificateRequest*(): seq[byte] =
  ## SignedMessage{type = SERVICE_CERTIFICATE_REQUEST} with no body.
  var w = ProtoWriter(buf: @[])
  w.putVarint(1, uint64(smServiceCertificateRequest))
  w.finish()

# ===========================================================================
# Decoders (response path)
# ===========================================================================

type
  SignedMessageView* = object
    msgType*: int           ## -1 if absent
    msg*: seq[byte]
    hasMsg*: bool
    signature*: seq[byte]
    hasSignature*: bool
    sessionKey*: seq[byte]
    hasSessionKey*: bool

proc decodeSignedMessage*(data: seq[byte]): SignedMessageView =
  result = SignedMessageView(msgType: -1, msg: @[], hasMsg: false,
                             signature: @[], hasSignature: false,
                             sessionKey: @[], hasSessionKey: false)
  var r = initReader(data)
  var f = WireField(number: 0, wire: 0, u64: 0'u64, bytesStart: 0, bytesLen: 0)
  while r.nextField(f):
    case f.number
    of 1:
      if f.wire == 0: result.msgType = int(f.u64)
    of 2:
      if f.wire == 2:
        result.msg = r.fieldBytes(f)
        result.hasMsg = true
    of 3:
      if f.wire == 2:
        result.signature = r.fieldBytes(f)
        result.hasSignature = true
    of 4:
      if f.wire == 2:
        result.sessionKey = r.fieldBytes(f)
        result.hasSessionKey = true
    else:
      discard

type
  KeyContainerView* = object
    id*: seq[byte]
    hasId*: bool
    iv*: seq[byte]
    hasIv*: bool
    key*: seq[byte]
    hasKey*: bool
    keyType*: int           ## -1 if absent
    trackLabel*: string

proc decodeKeyContainer(data: seq[byte]): KeyContainerView =
  result = KeyContainerView(id: @[], hasId: false, iv: @[], hasIv: false,
                            key: @[], hasKey: false, keyType: -1, trackLabel: "")
  var r = initReader(data)
  var f = WireField(number: 0, wire: 0, u64: 0'u64, bytesStart: 0, bytesLen: 0)
  while r.nextField(f):
    case f.number
    of 1:
      if f.wire == 2:
        result.id = r.fieldBytes(f)
        result.hasId = true
    of 2:
      if f.wire == 2:
        result.iv = r.fieldBytes(f)
        result.hasIv = true
    of 3:
      if f.wire == 2:
        result.key = r.fieldBytes(f)
        result.hasKey = true
    of 4:
      if f.wire == 0: result.keyType = int(f.u64)
    of 12:
      if f.wire == 2: result.trackLabel = r.fieldString(f)
    else:
      discard

proc decodeLicenseKeys*(licenseBytes: seq[byte]): seq[KeyContainerView] =
  ## Walk a License message, returning every KeyContainer (field 3).
  result = @[]
  var r = initReader(licenseBytes)
  var f = WireField(number: 0, wire: 0, u64: 0'u64, bytesStart: 0, bytesLen: 0)
  while r.nextField(f):
    if f.number == 3 and f.wire == 2:
      result.add decodeKeyContainer(r.fieldBytes(f))

type
  SignedDrmCertView* = object
    drmCertificate*: seq[byte]
    hasDrmCertificate*: bool
    signature*: seq[byte]
    hasSignature*: bool

proc decodeSignedDrmDeviceCertificate*(data: seq[byte]): SignedDrmCertView =
  result = SignedDrmCertView(drmCertificate: @[], hasDrmCertificate: false,
                             signature: @[], hasSignature: false)
  var r = initReader(data)
  var f = WireField(number: 0, wire: 0, u64: 0'u64, bytesStart: 0, bytesLen: 0)
  while r.nextField(f):
    case f.number
    of 1:
      if f.wire == 2:
        result.drmCertificate = r.fieldBytes(f)
        result.hasDrmCertificate = true
    of 2:
      if f.wire == 2:
        result.signature = r.fieldBytes(f)
        result.hasSignature = true
    else:
      discard

type
  DrmCertView* = object
    certType*: int          ## -1 if absent
    serialNumber*: seq[byte]
    hasSerial*: bool
    publicKey*: seq[byte]
    hasPublicKey*: bool
    providerId*: string

proc decodeDrmDeviceCertificate*(data: seq[byte]): DrmCertView =
  result = DrmCertView(certType: -1, serialNumber: @[], hasSerial: false,
                       publicKey: @[], hasPublicKey: false, providerId: "")
  var r = initReader(data)
  var f = WireField(number: 0, wire: 0, u64: 0'u64, bytesStart: 0, bytesLen: 0)
  while r.nextField(f):
    case f.number
    of 1:
      if f.wire == 0: result.certType = int(f.u64)
    of 2:
      if f.wire == 2:
        result.serialNumber = r.fieldBytes(f)
        result.hasSerial = true
    of 4:
      if f.wire == 2:
        result.publicKey = r.fieldBytes(f)
        result.hasPublicKey = true
    of 7:
      if f.wire == 2: result.providerId = r.fieldString(f)
    else:
      discard
