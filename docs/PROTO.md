# Widevine protobuf subset used by the CDM

Canonical source: pywidevine `license_protocol.proto` (full copy in
`docs/license_protocol.proto`). This lists ONLY the messages/fields this CDM
actually encodes or decodes, with exact field numbers and wire types. proto2
semantics; every field is optional/repeated. Tag = `(field << 3) | wire_type`.
Wire types used here: **0** = varint (int32/int64/uint32/bool/enum), **2** =
length-delimited (bytes/string/embedded message/packed-repeated).

Key simplification: a **`ClientIdentification`** is never parsed. The `.wvd`
already holds it pre-serialized; we treat it as opaque bytes — embed directly
as `LicenseRequest.client_id`, or AES-encrypt the raw bytes for the encrypted
path. So no ClientIdentification schema is needed.

## SignedMessage
| field | # | wire | type |
|---|---|---|---|
| type | 1 | 0 | enum MessageType |
| msg | 2 | 2 | bytes |
| signature | 3 | 2 | bytes |
| session_key | 4 | 2 | bytes |

`MessageType`: LICENSE_REQUEST=1, LICENSE=2, ERROR_RESPONSE=3,
SERVICE_CERTIFICATE_REQUEST=4, SERVICE_CERTIFICATE=5.

## LicenseRequest  (encode only)
| field | # | wire | type |
|---|---|---|---|
| client_id | 1 | 2 | bytes (opaque ClientIdentification) |
| content_id | 2 | 2 | message ContentIdentification |
| type | 3 | 0 | enum RequestType (NEW=1) |
| request_time | 4 | 0 | int64 |
| key_control_nonce_deprecated | 5 | 2 | bytes (unused) |
| protocol_version | 6 | 0 | enum ProtocolVersion (VERSION_2_1=21) |
| key_control_nonce | 7 | 0 | uint32 |
| encrypted_client_id | 8 | 2 | message EncryptedClientIdentification |

## ContentIdentification  (encode only; a oneof — set exactly one)
| field | # | wire | type |
|---|---|---|---|
| widevine_pssh_data | 1 | 2 | message WidevinePsshData (the CENC path) |
| webm_key_id | 2 | 2 | message WebmKeyId |
| init_data | 4 | 2 | message InitData |

**WidevinePsshData** (the field openwv calls `cenc_id_deprecated`):
pssh_data=1 (repeated bytes — the raw Widevine PSSH payload), license_type=2
(enum LicenseType), request_id=3 (bytes, random 16).

**WebmKeyId**: header=1 (bytes), license_type=2, request_id=3.

`LicenseType`: STREAMING=1, OFFLINE=2.

## EncryptedClientIdentification  (encode only)
provider_id=1 (string), service_certificate_serial_number=2 (bytes),
encrypted_client_id=3 (bytes), encrypted_client_id_iv=4 (bytes),
encrypted_privacy_key=5 (bytes).

## License  (decode only)
id=1 (msg, ignored), policy=2 (msg, ignored), **key=3 (repeated KeyContainer)**,
license_start_time=4 (int64), … (rest ignored).

## License.KeyContainer  (decode only)
| field | # | wire | type |
|---|---|---|---|
| id | 1 | 2 | bytes (key id) |
| iv | 2 | 2 | bytes |
| key | 3 | 2 | bytes (AES-CBC-encrypted content key) |
| type | 4 | 0 | enum KeyType |
| level | 5 | 0 | enum SecurityLevel |
| track_label | 12 | 2 | string |

`KeyType`: SIGNING=1, CONTENT=2, KEY_CONTROL=3, OPERATOR_SESSION=4,
ENTITLEMENT=5, OEM_CONTENT=6.

## SignedDrmDeviceCertificate  (decode only)
drm_certificate=1 (bytes), signature=2 (bytes), signer=3 (msg, ignored).

## DrmDeviceCertificate  (decode only)
type=1 (enum CertificateType), serial_number=2 (bytes),
creation_time_seconds=3 (uint32), public_key=4 (bytes, PKCS#1 DER),
system_id=5 (uint32), provider_id=7 (string).

`CertificateType`: ROOT=0, DRM_INTERMEDIATE=1, DRM_USER_DEVICE=2, SERVICE=3,
PROVISIONER=4.
