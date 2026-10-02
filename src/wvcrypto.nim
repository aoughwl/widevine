## Bindings to the flat crypto ABI (cpp/wvcrypto.c, backed by mbedTLS) plus
## ergonomic wrappers that work in terms of seq[byte]. The {.compile.} of
## wvcrypto.c and the mbedTLS link flags live in the main module (widevine.nim).

{.passC: "-I../cpp".}

# --- raw bindings ----------------------------------------------------------

proc wvc_sha1(msg: ptr byte, len: csize_t, outp: ptr byte): cint {.importc, header: "wvcrypto.h".}
proc wvc_sha256(msg: ptr byte, len: csize_t, outp: ptr byte): cint {.importc, header: "wvcrypto.h".}
proc wvc_hmac_sha256(key: ptr byte, klen: csize_t, msg: ptr byte, mlen: csize_t,
                     outp: ptr byte): cint {.importc, header: "wvcrypto.h".}
proc wvc_aes128_cmac(key: ptr byte, msg: ptr byte, mlen: csize_t,
                     outp: ptr byte): cint {.importc, header: "wvcrypto.h".}
proc wvc_aes128_ctr(key: ptr byte, iv: ptr byte, buf: ptr byte,
                    len: csize_t): cint {.importc, header: "wvcrypto.h".}
proc wvc_aes128_cbc_decrypt(key: ptr byte, iv: ptr byte, buf: ptr byte,
                            len: csize_t): cint {.importc, header: "wvcrypto.h".}
proc wvc_aes128_cbc_decrypt_pkcs7(key: ptr byte, iv: ptr byte, inp: ptr byte,
                                  ilen: csize_t, outp: ptr byte, ocap: csize_t,
                                  olen: ptr csize_t): cint {.importc, header: "wvcrypto.h".}
proc wvc_aes128_cbc_encrypt_pkcs7(key: ptr byte, iv: ptr byte, inp: ptr byte,
                                  ilen: csize_t, outp: ptr byte, ocap: csize_t,
                                  olen: ptr csize_t): cint {.importc, header: "wvcrypto.h".}
proc wvc_rsa_pss_sha1_sign(der: ptr byte, dlen: csize_t, msg: ptr byte,
                           mlen: csize_t, sig: ptr byte, scap: csize_t,
                           slen: ptr csize_t): cint {.importc, header: "wvcrypto.h".}
proc wvc_rsa_pss_sha1_verify(der: ptr byte, dlen: csize_t, msg: ptr byte,
                             mlen: csize_t, sig: ptr byte,
                             slen: csize_t): cint {.importc, header: "wvcrypto.h".}
proc wvc_rsa_oaep_sha1_decrypt(der: ptr byte, dlen: csize_t, ct: ptr byte,
                               ctlen: csize_t, outp: ptr byte, ocap: csize_t,
                               olen: ptr csize_t): cint {.importc, header: "wvcrypto.h".}
proc wvc_rsa_oaep_sha1_encrypt(der: ptr byte, dlen: csize_t, pt: ptr byte,
                               ptlen: csize_t, outp: ptr byte, ocap: csize_t,
                               olen: ptr csize_t): cint {.importc, header: "wvcrypto.h".}
proc wvc_random(outp: ptr byte, len: csize_t): cint {.importc, header: "wvcrypto.h".}

# --- helpers ---------------------------------------------------------------

proc p(s: seq[byte]): ptr byte =
  ## Pointer to a seq's first byte, or a null pointer when empty (the C side
  ## never dereferences a zero-length buffer).
  if s.len == 0: cast[ptr byte](0)
  else: addr s[0]

proc newBuf(n: int): seq[byte] =
  result = @[]
  result.grow n, 0'u8

# --- ergonomic wrappers ----------------------------------------------------

proc sha1*(msg: seq[byte]): seq[byte] =
  result = newBuf(20)
  discard wvc_sha1(p(msg), csize_t(msg.len), addr result[0])

proc sha256*(msg: seq[byte]): seq[byte] =
  result = newBuf(32)
  discard wvc_sha256(p(msg), csize_t(msg.len), addr result[0])

proc hmacSha256*(key: seq[byte], msg: seq[byte]): seq[byte] =
  result = newBuf(32)
  discard wvc_hmac_sha256(p(key), csize_t(key.len), p(msg), csize_t(msg.len),
                          addr result[0])

proc aes128Cmac*(key: seq[byte], msg: seq[byte]): seq[byte] =
  result = newBuf(16)
  discard wvc_aes128_cmac(p(key), p(msg), csize_t(msg.len), addr result[0])

proc aes128CtrInPlace*(key: seq[byte], iv: seq[byte], buf: var seq[byte]): bool =
  if buf.len == 0: return true
  wvc_aes128_ctr(p(key), p(iv), addr buf[0], csize_t(buf.len)) == 0

proc aes128CbcDecryptInPlace*(key: seq[byte], iv: seq[byte], buf: var seq[byte]): bool =
  if buf.len == 0: return true
  wvc_aes128_cbc_decrypt(p(key), p(iv), addr buf[0], csize_t(buf.len)) == 0

proc aes128CbcDecryptPkcs7*(key: seq[byte], iv: seq[byte], data: seq[byte],
                            ok: var bool): seq[byte] =
  var outb = newBuf(if data.len == 0: 16 else: data.len)
  var olen: csize_t = 0
  let rc = wvc_aes128_cbc_decrypt_pkcs7(p(key), p(iv), p(data), csize_t(data.len),
                                        addr outb[0], csize_t(outb.len), addr olen)
  ok = rc == 0
  outb.shrink int(olen)
  outb

proc aes128CbcEncryptPkcs7*(key: seq[byte], iv: seq[byte], data: seq[byte],
                            ok: var bool): seq[byte] =
  var outb = newBuf(data.len + 16)
  var olen: csize_t = 0
  let rc = wvc_aes128_cbc_encrypt_pkcs7(p(key), p(iv), p(data), csize_t(data.len),
                                        addr outb[0], csize_t(outb.len), addr olen)
  ok = rc == 0
  outb.shrink int(olen)
  outb

proc rsaPssSha1Sign*(privDer: seq[byte], msg: seq[byte], ok: var bool): seq[byte] =
  var outb = newBuf(512)
  var slen: csize_t = 0
  let rc = wvc_rsa_pss_sha1_sign(p(privDer), csize_t(privDer.len), p(msg),
                                 csize_t(msg.len), addr outb[0],
                                 csize_t(outb.len), addr slen)
  ok = rc == 0
  outb.shrink int(slen)
  outb

proc rsaPssSha1Verify*(pubDer: seq[byte], msg: seq[byte], sig: seq[byte]): bool =
  wvc_rsa_pss_sha1_verify(p(pubDer), csize_t(pubDer.len), p(msg),
                          csize_t(msg.len), p(sig), csize_t(sig.len)) == 0

proc rsaOaepSha1Decrypt*(privDer: seq[byte], ct: seq[byte], ok: var bool): seq[byte] =
  var outb = newBuf(512)
  var olen: csize_t = 0
  let rc = wvc_rsa_oaep_sha1_decrypt(p(privDer), csize_t(privDer.len), p(ct),
                                     csize_t(ct.len), addr outb[0],
                                     csize_t(outb.len), addr olen)
  ok = rc == 0
  outb.shrink int(olen)
  outb

proc rsaOaepSha1Encrypt*(pubDer: seq[byte], pt: seq[byte], ok: var bool): seq[byte] =
  var outb = newBuf(512)
  var olen: csize_t = 0
  let rc = wvc_rsa_oaep_sha1_encrypt(p(pubDer), csize_t(pubDer.len), p(pt),
                                     csize_t(pt.len), addr outb[0],
                                     csize_t(outb.len), addr olen)
  ok = rc == 0
  outb.shrink int(olen)
  outb

proc randomBytes*(n: int): seq[byte] =
  result = newBuf(n)
  if n > 0:
    discard wvc_random(addr result[0], csize_t(n))
