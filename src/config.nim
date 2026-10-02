## Compile-time configuration (openwv's config.rs). Because the CDM cannot read
## files at runtime, the device identity and policy are baked in at build time.

import embedded_device

type
  EncryptClientId* = enum
    ## When to encrypt the ClientIdentification in license requests.
    eciNever            ## always send plaintext client id
    eciIfCertificateSet ## encrypt only if setServerCertificate() was called
    eciAlways           ## always encrypt (fetch a service cert if needed)

const encryptPolicy* = eciAlways

proc widevineDeviceBytes*(): seq[byte] =
  ## The embedded `.wvd` bytes (empty if none was baked in).
  embeddedDevice()
