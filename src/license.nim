## License request building, session-key derivation (KDF), and key loading.
## Mirrors openwv's license.rs. See docs/ALGORITHMS.md §3–§5.

import messages, wvcrypto, contentkey, util, wvd, servicecert

type
  LicenseError* = enum
    leNone, leBadSignedMessage, leBadProto, leNoSessionKey, leBadSessionKeyCrypto,
    leBadKeyDerivation, leBadSignature, leBadContentKey, leEncryptFailed

# --- helpers ---------------------------------------------------------------

proc u32be(v: uint32): seq[byte] =
  @[byte(v shr 24), byte(v shr 16), byte(v shr 8), byte(v)]

proc randomU32(): uint32 =
  let r = randomBytes(4)
  (uint32(r[0]) shl 24) or (uint32(r[1]) shl 16) or (uint32(r[2]) shl 8) or uint32(r[3])

# --- request ---------------------------------------------------------------

proc requestLicense*(contentId: seq[byte], haveCert: bool, cert: ServerCertificate,
                     device: WidevineDevice, signedMsg: var seq[byte],
                     requestBytes: var seq[byte]): bool =
  ## Build a signed LicenseRequest. `requestBytes` (the serialized inner
  ## LicenseRequest) is returned for later use as the KDF context.
  let nonce = randomU32()
  let reqTime = nowSeconds()

  if haveCert:
    var encClientId: seq[byte] = @[]
    if not encryptClientId(cert, device.clientId, encClientId):
      return false
    requestBytes = encLicenseRequestEncrypted(contentId, encClientId, reqTime, nonce)
  else:
    requestBytes = encLicenseRequestPlain(contentId, device.clientId, reqTime, nonce)

  var ok = false
  let signature = rsaPssSha1Sign(device.privateKey, requestBytes, ok)
  if not ok:
    return false

  signedMsg = encSignedMessage(smLicenseRequest, requestBytes, signature)
  true

# --- session-key derivation ------------------------------------------------

type
  SessionKeys = object
    encryption: seq[byte]   ## 16
    macServer: seq[byte]    ## 32

proc deriveKey(sessionKey: seq[byte], counter: byte, label: string,
               keySizeBits: uint32, requestMsg: seq[byte]): seq[byte] =
  var msg: seq[byte] = @[]
  msg.add counter
  for b in toBytes(label):
    msg.add b
  msg.add 0'u8
  for b in requestMsg:
    msg.add b
  for b in u32be(keySizeBits):
    msg.add b
  aes128Cmac(sessionKey, msg)

proc deriveSessionKeys(requestMsg: seq[byte], sessionKey: seq[byte]): SessionKeys =
  const authLabel = "AUTHENTICATION"
  let enc = deriveKey(sessionKey, 1'u8, "ENCRYPTION", 128'u32, requestMsg)
  let s1 = deriveKey(sessionKey, 1'u8, authLabel, 512'u32, requestMsg)
  let s2 = deriveKey(sessionKey, 2'u8, authLabel, 512'u32, requestMsg)
  var macServer: seq[byte] = @[]
  for b in s1: macServer.add b
  for b in s2: macServer.add b
  SessionKeys(encryption: enc, macServer: macServer)

# --- response --------------------------------------------------------------

proc loadLicenseKeys*(responseBytes: seq[byte], requestBytes: seq[byte],
                      device: WidevineDevice, keys: var seq[ContentKey],
                      addedKeys: var bool, err: var LicenseError): bool =
  addedKeys = false
  err = leNone

  let resp = decodeSignedMessage(responseBytes)
  if resp.msgType != smLicense:
    err = leBadSignedMessage
    return false
  if not resp.hasSessionKey:
    err = leNoSessionKey
    return false
  if not resp.hasMsg:
    err = leBadSignedMessage
    return false

  var ok = false
  let sessionKey = rsaOaepSha1Decrypt(device.privateKey, resp.sessionKey, ok)
  if not ok:
    err = leBadSessionKeyCrypto
    return false

  let sk = deriveSessionKeys(requestBytes, sessionKey)

  # Verify the license signature: HMAC-SHA256(mac_server, msg).
  let expectedSig = hmacSha256(sk.macServer, resp.msg)
  if not (resp.hasSignature and bytesEqual(expectedSig, resp.signature)):
    err = leBadSignature
    return false

  for kc in decodeLicenseKeys(resp.msg):
    if not kc.hasIv or not kc.hasKey:
      continue
    var dok = false
    let data = aes128CbcDecryptPkcs7(sk.encryption, kc.iv, kc.key, dok)
    if not dok:
      err = leBadContentKey
      return false
    var label = kc.trackLabel
    keys.add ContentKey(id: kc.id, hasId: kc.hasId, data: data,
                        keyType: kc.keyType, trackLabel: label)
    addedKeys = true

  true
