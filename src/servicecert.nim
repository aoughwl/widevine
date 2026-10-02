## Service (server) certificate: parse + verify, and Client ID encryption.
## Mirrors openwv's service_certificate.rs.

import messages, wvcrypto, rootcert

type
  ServerCertificate* = object
    publicKey*: seq[byte]    ## PKCS#1 DER RSA public key of the service
    serialNumber*: seq[byte]
    providerId*: string

  ServiceCertError* = enum
    sceNone, sceEmpty, sceBadProto, sceMissingFields, sceBadSignature,
    sceWrongType

proc parseServiceCertificate*(certBytes: seq[byte], cert: var ServerCertificate,
                              err: var ServiceCertError): bool =
  ## Parse a raw SignedDrmDeviceCertificate, verify it against the Widevine
  ## root key, and extract the service public key / serial / provider.
  cert = ServerCertificate(publicKey: @[], serialNumber: @[], providerId: "")
  err = sceNone
  if certBytes.len == 0:
    err = sceEmpty
    return false

  let signed = decodeSignedDrmDeviceCertificate(certBytes)
  if not signed.hasDrmCertificate or not signed.hasSignature:
    err = sceMissingFields
    return false

  if not rsaPssSha1Verify(serviceCertRootPubKey(), signed.drmCertificate,
                          signed.signature):
    err = sceBadSignature
    return false

  let c = decodeDrmDeviceCertificate(signed.drmCertificate)
  if c.certType < 0 or not c.hasPublicKey or not c.hasSerial:
    err = sceMissingFields
    return false
  if c.certType != certTypeService:
    err = sceWrongType
    return false

  cert = ServerCertificate(publicKey: c.publicKey, serialNumber: c.serialNumber,
                           providerId: c.providerId)
  true

proc parseServiceCertMessage*(messageBytes: seq[byte], cert: var ServerCertificate,
                              err: var ServiceCertError): bool =
  ## Parse a SignedMessage{SERVICE_CERTIFICATE} then its inner certificate.
  let sm = decodeSignedMessage(messageBytes)
  if sm.msgType != smServiceCertificate or not sm.hasMsg:
    err = sceBadProto
    return false
  parseServiceCertificate(sm.msg, cert, err)

proc encryptClientId*(cert: ServerCertificate, clientId: seq[byte],
                      outMsg: var seq[byte]): bool =
  ## Build an EncryptedClientIdentification: AES-128-CBC(PKCS7) the client id
  ## under a random privacy key, then RSA-OAEP that key to the service.
  let privacyKey = randomBytes(16)
  let privacyIv = randomBytes(16)

  var ok = false
  let encClientId = aes128CbcEncryptPkcs7(privacyKey, privacyIv, clientId, ok)
  if not ok:
    return false

  let encPrivacyKey = rsaOaepSha1Encrypt(cert.publicKey, privacyKey, ok)
  if not ok:
    return false

  outMsg = encEncryptedClientId(cert.providerId, cert.serialNumber,
                                encClientId, privacyIv, encPrivacyKey)
  true
