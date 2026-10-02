## Mirrors of the Widevine CDM ABI enums (see third-party/cdm and docs). These
## integer values cross the C ABI as plain uint32, so they must match exactly.

# cdm::EncryptionScheme
const
  esUnencrypted* = 0'u32
  esCenc* = 1'u32
  esCbcs* = 2'u32

# cdm::Status
const
  stSuccess* = 0'i32
  stNeedMoreData* = 1'i32
  stNoKey* = 2'i32
  stInitializationError* = 3'i32
  stDecryptError* = 4'i32
  stDecodeError* = 5'i32
  stDeferredInitialization* = 6'i32

# cdm::Exception
const
  excTypeError* = 0'u32
  excNotSupportedError* = 1'u32
  excInvalidStateError* = 2'u32
  excQuotaExceededError* = 3'u32

# cdm::KeyStatus
const
  ksUsable* = 0'u32
  ksInternalError* = 1'u32
  ksExpired* = 2'u32
  ksOutputRestricted* = 3'u32
  ksOutputDownscaled* = 4'u32
  ksStatusPending* = 5'u32
  ksReleased* = 6'u32

# cdm::InitDataType
const
  idtCenc* = 0'u32
  idtKeyIds* = 1'u32
  idtWebM* = 2'u32

# cdm::SessionType
const
  sessTemporary* = 0'u32
  sessPersistentLicense* = 1'u32

# cdm::MessageType
const
  mtLicenseRequest* = 0'u32
  mtLicenseRenewal* = 1'u32
  mtLicenseRelease* = 2'u32
  mtIndividualizationRequest* = 3'u32
