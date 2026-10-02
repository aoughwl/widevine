# Widevine CDM — Algorithm Reference

A precise, self-contained reference for reimplementing the Widevine CDM client flow,
cross-checked against **pywidevine** (`devine-dl/pywidevine`) and **openwv** (Rust).
All multi-byte integers are **big-endian** unless stated otherwise.

Protobuf messages referenced here are from Widevine's `license_protocol.proto`
(`SignedMessage`, `LicenseRequest`, `License`, `ClientIdentification`,
`EncryptedClientIdentification`, `SignedDrmDeviceCertificate` / `DrmDeviceCertificate`).

---

## 1. `.wvd` file format (pywidevine `Device`)

Fixed header, parsed by `Device.loads` (a `construct.Struct`) and written by `Device.dumps`.
All integers big-endian. Field order, in bytes:

| Field              | Type                         | Notes |
|--------------------|------------------------------|-------|
| magic              | 3 bytes = `b"WVD"`           | `Const(b"WVD")` |
| version            | u8                           | `1` or `2` |
| type_              | u8                           | enum: `CHROME=1`, `ANDROID=2` |
| security_level     | u8                           | e.g. 1, 2, 3 (L1/L2/L3) |
| flags              | 1 byte                       | padded bitfield; normally `0x00` |
| private_key_length | u16-BE                       | |
| private_key        | `private_key_length` bytes   | **PKCS#1 DER** RSA private key |
| client_id_length   | u16-BE                       | |
| client_id          | `client_id_length` bytes     | serialized `ClientIdentification` protobuf |

So the fixed prefix is **11 bytes** (`3 + 1 + 1 + 1 + 1 + 2` up through `private_key_length`;
the two length-prefixed blobs follow).

Equivalent `struct` view of the header up to the first length:
`>3sBBBB` → magic, version, type_, security_level, flags; then `>H` + blob, `>H` + blob.

**v1 vs v2:**
- **v2** (current): ends after `client_id` as above.
- **v1** (legacy): identical, but appends two more fields after `client_id`:
  `vmp_length` (u16-BE) + `vmp` (`vmp_length` bytes, a serialized `FileHashes` / VMP blob).
  v2 folds VMP into the `ClientIdentification` instead, so it has no trailing VMP fields.

The `version` byte is a `Const` per struct (1 for the v1 struct, 2 for the v2 struct);
pywidevine picks the struct by the version byte it reads.

---

## 2. PSSH / CENC init data parsing

A `pssh` box is an ISO BMFF (ISO/IEC 14496-12) full box. Byte layout:

| Offset | Size | Field |
|--------|------|-------|
| 0      | 4    | `size` (u32-BE), total box length including these 4 bytes |
| 4      | 4    | type = `b"pssh"` |
| 8      | 1    | version (0 or 1) |
| 9      | 3    | flags |
| 12…    | …    | **if version > 0:** `kid_count` (u32-BE) followed by `kid_count` × 16-byte KIDs |
| …      | 4    | `data_size` (u32-BE) |
| …      | `data_size` | `data` = Widevine PSSH data (a serialized `WidevinePsshData` protobuf) |

Immediately after the `type` there is a 16-byte **SystemID** (UUID) in the full-box layout:
in a complete box it sits at bytes `[8+4 .. ]`? — see the two parsers below, which differ:

**Widevine System ID (UUID):** `edef8ba9-79d6-4ace-a3c8-27dcd51d21ed`
(raw bytes `ED EF 8B A9 79 D6 4A CE A3 C8 27 DC D5 1D 21 ED`).

**pywidevine (`pssh.py`):** delegates to `pymp4`'s `Box.parse(data)`, which yields a parsed
box with `.version`, `.flags`, `.system_ID`, `.key_IDs`, `.init_data`. The SystemID is the
16-byte UUID that follows version+flags; `init_data` is the `data` blob. Widevine's UUID is
`UUID(hex="edef8ba979d64acea3c827dcd51d21ed")`. pywidevine will also accept bare Widevine
PSSH *data* (a raw `WidevinePsshData` protobuf) not wrapped in a box.

**openwv (strict, version-0 only):** rejects any `pssh` box whose version byte ≠ 0, and reads
fixed offsets into the box payload:
- `systemID` = bytes `[4 .. 20]` (16 bytes),
- `data_size` = u32-BE at `[20 .. 24]`,
- `data` = bytes `[24 .. 24 + data_size]`.

Note these offsets are relative to the start of the **box body passed to openwv** (i.e. after
any outer `size`/`type` has been stripped, so byte 0 = version/flags word). Concretely, in that
view: offset 0 = version(1)+flags(3), offset 4..20 = SystemID, offset 20..24 = data_size,
offset 24.. = data. openwv requires `systemID == Widevine UUID` and version 0 (no KID list).

The `data` blob in both cases is the Widevine PSSH data: a `WidevinePsshData` protobuf whose
`pssh_data` / key-id content is what goes into the license request's `content_id`.

---

## 3. License request building

Build a `LicenseRequest` protobuf (pywidevine `Cdm.get_license_challenge`):

```
LicenseRequest {
  content_id = ContentIdentification {
    widevine_pssh_data = WidevinePsshData {
      pssh_data   = [ pssh.init_data ],   // the box's data blob
      license_type = license_type,        // e.g. STREAMING / OFFLINE
      request_id   = request_id            // random, identifies this session
    }
  }
  type              = NEW
  request_time      = int(time.time())     // current unix seconds
  protocol_version  = VERSION_2_1          // == 21
  key_control_nonce = random u32 in [1, 2^31)
  // exactly one identity field:
  client_id           = <ClientIdentification>           // plaintext, no privacy mode
  encrypted_client_id = <EncryptedClientIdentification>  // privacy mode (see §6)
}
```

Use `client_id` when there is no service certificate / privacy mode is off; otherwise use
`encrypted_client_id` and omit `client_id`.

**Signing and wrapping:**
1. Serialize the `LicenseRequest` → `request_bytes`.
2. `signature = RSA-PSS(SHA1).sign( SHA1(request_bytes) )` using the device private key
   (pywidevine: `pss.new(rsa_key).sign(SHA1.new(license_request))` where `license_request`
   is the serialized bytes). PSS with SHA-1 for both digest and MGF1, default salt length.
3. Wrap:
   ```
   SignedMessage {
     type      = LICENSE_REQUEST
     msg       = request_bytes        // the EXACT serialized LicenseRequest
     signature = signature
   }
   ```
   Serialize the `SignedMessage` → this is the license challenge sent to the server.

**The exact bytes that are signed = the serialized `LicenseRequest` (`request_bytes`).**
This same `request_bytes` is reused verbatim as the KDF context input in §4 — keep it around.

---

## 4. Session key derivation (CMAC-based KDF)

Inputs:
- `session_key` (16 bytes) = `RSA-OAEP(SHA1).decrypt(SignedMessage_response.session_key)`
  using the device private key (pywidevine: `PKCS1_OAEP.new(rsa_key)` with SHA-1).
- `request_msg` = the serialized `LicenseRequest` bytes from §3 (the bytes that were signed).

AES-128-CMAC is keyed by `session_key`. One derived 16-byte block per counter:

```
derive(counter, context) = AES128_CMAC( key = session_key,
                                         data = counter_u8 || context )
```
where `counter_u8` is a single byte and `context` is built per label:

```
context(label, key_size_bits) = label || 0x00 || request_msg || key_size_u32_BE
```

- **Encryption context:** `label = b"ENCRYPTION"`, `key_size_bits = 128` (`16*8`).
- **Authentication context:** `label = b"AUTHENTICATION"`, `key_size_bits = 512` (`32*8*2`).

`key_size_u32_BE` = `key_size_bits.to_bytes(4, "big")`. The `0x00` is a single separator byte.

Derivation (matches pywidevine `derive_keys`):

```
enc_key          = derive(1, enc_context)                       # 16 bytes
mac_key_server   = derive(1, mac_context) || derive(2, mac_context)   # 32 bytes
mac_key_client   = derive(3, mac_context) || derive(4, mac_context)   # 32 bytes
```

So the full CMAC input for, e.g., the first server-MAC block is:
`0x01 || b"AUTHENTICATION" || 0x00 || request_msg || 00 00 02 00`
(`0x00000200` = 512). The encryption block is:
`0x01 || b"ENCRYPTION" || 0x00 || request_msg || 00 00 00 80` (`0x80` = 128).

- `enc_key` (16 B) — decrypts content keys (§5).
- `mac_key_server` (32 B) — verifies the license response signature (§5).
- `mac_key_client` (32 B) — derived for completeness (used when the client must MAC messages).

---

## 5. License response verification & key decryption

The response is a `SignedMessage { type = LICENSE, msg = <License>, signature, ... }`.

**Signature verification (HMAC-SHA256 with `mac_key_server`):**
```
computed = HMAC_SHA256( key = mac_key_server,
                        data = (oemcrypto_core_message or b"") || msg )
assert computed == SignedMessage.signature
```
pywidevine prepends `license_message.oemcrypto_core_message` (empty bytes if absent) and then
the `msg` field, in that order, into a single HMAC-SHA256 over the whole, keyed by the 32-byte
`mac_key_server`. Mismatch → reject (`SignatureMismatch`).

**Key decryption:** parse `msg` as a `License` protobuf. For each `key` in `License.key`
(pywidevine `Key.from_key_container(key, enc_key)`):
```
plaintext_key = PKCS7_unpad(
    AES-128-CBC( key = enc_key, iv = key.iv ).decrypt( key.key ),
    block_size = 16 )
```
`key.iv` is the per-key 16-byte IV; `key.key` is the encrypted key bytes. AES-128-CBC with
`enc_key`, then strip PKCS#7 padding (block size 16). Each key container also carries `type`
(e.g. CONTENT, SIGNING) and a `key_id`.

---

## 6. Service / server certificate

### 6a. Encrypting the ClientIdentification (privacy mode)

pywidevine `encrypt_client_id` builds an `EncryptedClientIdentification`:

1. `privacy_key = get_random_bytes(16)`   (16-byte AES key)
2. `privacy_iv  = get_random_bytes(16)`   (16-byte IV)
3. `enc_client  = AES-128-CBC( key = privacy_key, iv = privacy_iv ).encrypt(
                     PKCS7_pad( serialized ClientIdentification, 16 ) )`
4. `enc_privacy_key = RSA-OAEP(SHA1).encrypt( privacy_key )` using the **service certificate's
   public key** (the `DrmDeviceCertificate.public_key`, PKCS#1 DER).

Resulting fields:
```
EncryptedClientIdentification {
  provider_id                        = service_cert.provider_id
  service_certificate_serial_number  = service_cert.serial_number
  encrypted_client_id                = enc_client
  encrypted_client_id_iv             = privacy_iv
  encrypted_privacy_key              = enc_privacy_key
}
```
This is placed in `LicenseRequest.encrypted_client_id` (§3), omitting plaintext `client_id`.

### 6b. Parsing / verifying the service certificate

pywidevine `set_service_certificate` accepts the certificate as base64 or raw bytes and
parses it as a `SignedDrmDeviceCertificate` (possibly first unwrapping a `SignedMessage`
whose `msg` holds it).

**Verify the certificate signature** against Widevine's known **root** public key, using
RSA-PSS with SHA-1 over the serialized inner certificate:
```
RSA-PSS(SHA1).verify(
    msg_hash  = SHA1( signed_drm_certificate.drm_certificate ),
    signature = signed_drm_certificate.signature,
    key       = root_cert.public_key )
```
(pywidevine: `pss.new(RSA.import_key(root_cert.public_key)).verify(...)`.)

On success, parse the inner `DrmDeviceCertificate` and require:
- `type == SERVICE` (it must be a service certificate, not a device cert),
- extract `public_key` (PKCS#1 DER — used for RSA-OAEP in §6a),
- extract `serial_number` and `provider_id` (used to populate the
  `EncryptedClientIdentification` fields in §6a).

---

## Crypto primitive summary

| Operation                        | Algorithm | Key |
|----------------------------------|-----------|-----|
| License request signature        | RSA-PSS, SHA-1 (sign) | device private key |
| Service cert signature verify    | RSA-PSS, SHA-1 (verify) | Widevine root public key |
| `session_key` decrypt            | RSA-OAEP, SHA-1 | device private key |
| `privacy_key` encrypt            | RSA-OAEP, SHA-1 | service cert public key |
| KDF (key derivation)             | AES-128-CMAC | `session_key` |
| License response signature       | HMAC-SHA256 | `mac_key_server` (32 B) |
| Content-ID encrypt (privacy)     | AES-128-CBC + PKCS7 | random `privacy_key` (16 B) |
| Content key decrypt              | AES-128-CBC + PKCS7 unpad | `enc_key` (16 B) |

All length prefixes in `.wvd` and `pssh` boxes are **big-endian**; KDF `key_size` and
`pssh` sizes are **big-endian** 4-byte / 2-byte integers as noted per field.
