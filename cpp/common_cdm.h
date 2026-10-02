#ifndef COMMON_CDM_H_
#define COMMON_CDM_H_

#include "content_decryption_module.h"

namespace cdm {

class CDM_CLASS_API CommonCdm : public cdm::ContentDecryptionModule_10,
                                public cdm::ContentDecryptionModule_11 {
 public:
  cdm::ContentDecryptionModule_10* As10() { return this; };
  cdm::ContentDecryptionModule_11* As11() { return this; };

  void Initialize(bool allow_distinctive_identifier,
                  bool allow_persistent_state,
                  bool use_hw_secure_codecs) override = 0;
  void GetStatusForPolicy(uint32_t promise_id,
                          const Policy& policy) override = 0;
  void SetServerCertificate(uint32_t promise_id,
                            const uint8_t* server_certificate_data,
                            uint32_t server_certificate_data_size) override = 0;
  void CreateSessionAndGenerateRequest(uint32_t promise_id,
                                       SessionType session_type,
                                       InitDataType init_data_type,
                                       const uint8_t* init_data,
                                       uint32_t init_data_size) override = 0;
  void LoadSession(uint32_t promise_id,
                   SessionType session_type,
                   const char* session_id,
                   uint32_t session_id_size) override = 0;
  void UpdateSession(uint32_t promise_id,
                     const char* session_id,
                     uint32_t session_id_size,
                     const uint8_t* response,
                     uint32_t response_size) override = 0;
  void CloseSession(uint32_t promise_id,
                    const char* session_id,
                    uint32_t session_id_size) override = 0;
  void RemoveSession(uint32_t promise_id,
                     const char* session_id,
                     uint32_t session_id_size) override = 0;
  void TimerExpired(void* context) override = 0;
  Status Decrypt(const InputBuffer_2& encrypted_buffer,
                 DecryptedBlock* decrypted_buffer) override = 0;
  Status InitializeAudioDecoder(
      const AudioDecoderConfig_2& audio_decoder_config) override = 0;
  Status InitializeVideoDecoder(
      const VideoDecoderConfig_2& video_decoder_config) override = 0;
  void DeinitializeDecoder(StreamType decoder_type) override = 0;
  void ResetDecoder(StreamType decoder_type) override = 0;
  Status DecryptAndDecodeFrame(const InputBuffer_2& encrypted_buffer,
                               VideoFrame* video_frame) override = 0;
  Status DecryptAndDecodeSamples(const InputBuffer_2& encrypted_buffer,
                                 AudioFrames* audio_frames) override = 0;
  void OnPlatformChallengeResponse(
      const PlatformChallengeResponse& response) override = 0;
  void OnQueryOutputProtectionStatus(QueryResult result,
                                     uint32_t link_mask,
                                     uint32_t output_protection_mask) override =
      0;
  void OnStorageId(uint32_t version,
                   const uint8_t* storage_id,
                   uint32_t storage_id_size) override = 0;
  void Destroy() override = 0;

 protected:
  CommonCdm() {}
  ~CommonCdm() {}
};

}  // namespace cdm

#endif  // COMMON_CDM_H_
