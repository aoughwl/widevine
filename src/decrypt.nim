## Content decryption: CENC (AES-CTR) and CBCS (AES-CBC + pattern), with
## subsample support. Mirrors openwv's decrypt.rs. Operates in place on a
## seq[byte] (the caller copies the host buffer in/out).

import wvcrypto, contentkey, cdmtypes

type
  Subsample* = object
    clear*: int
    cipher*: int

  DecryptStatus* = enum
    dsOk, dsNoKey, dsError

# Build the list of cipher (start,len) regions from subsamples, or one covering
# the whole buffer when there are none.
proc cipherRegions(dataLen: int, subs: seq[Subsample], ok: var bool): seq[Subsample] =
  ok = true
  result = @[]
  if subs.len == 0:
    result.add Subsample(clear: 0, cipher: dataLen)
    return
  var pos = 0
  for s in subs:
    pos += s.clear
    if pos + s.cipher > dataLen:
      ok = false
      return
    result.add Subsample(clear: pos, cipher: s.cipher)   # clear field reused as absolute start
    pos += s.cipher

proc sliceOut(data: seq[byte], start, length: int): seq[byte] =
  result = @[]
  for i in 0 ..< length:
    result.add data[start + i]

proc decryptCenc(key: ContentKey, iv: seq[byte], data: var seq[byte],
                 regions: seq[Subsample]): DecryptStatus =
  # Gather all cipher bytes into one buffer so the CTR keystream is continuous
  # across subsamples, decrypt once, scatter back.
  var gathered: seq[byte] = @[]
  for r in regions:
    for i in 0 ..< r.cipher:
      gathered.add data[r.clear + i]
  if not aes128CtrInPlace(key.data, iv, gathered):
    return dsError
  var g = 0
  for r in regions:
    for i in 0 ..< r.cipher:
      data[r.clear + i] = gathered[g]
      inc g
  dsOk

proc decryptCbcs(key: ContentKey, iv: seq[byte], data: var seq[byte],
                 regions: seq[Subsample], cryptBlocks0, skipBlocks: int): DecryptStatus =
  var cryptBlocks = cryptBlocks0
  if cryptBlocks == 0 and skipBlocks == 0:
    cryptBlocks = 1   # whole region encrypted (Chromium behaviour)
  # Running CBC IV, continued across every decrypted run in the sample.
  var runIv: seq[byte] = @[]
  for b in iv: runIv.add b

  for r in regions:
    var blockOff = 0
    let totalBlocks = r.cipher div 16
    while blockOff < totalBlocks:
      # decrypt up to cryptBlocks blocks
      let n = min(cryptBlocks, totalBlocks - blockOff)
      let start = r.clear + blockOff * 16
      let runLen = n * 16
      var chunk = sliceOut(data, start, runLen)
      # remember last ciphertext block to chain into the next run
      var nextIv: seq[byte] = @[]
      for i in 0 ..< 16:
        nextIv.add chunk[runLen - 16 + i]
      if not aes128CbcDecryptInPlace(key.data, runIv, chunk):
        return dsError
      for i in 0 ..< runLen:
        data[start + i] = chunk[i]
      runIv = nextIv
      blockOff += n
      if blockOff >= totalBlocks:
        break
      # skip skipBlocks (left as clear), not fed into the chain
      blockOff += skipBlocks
  dsOk

proc decryptBuf*(hasKey: bool, key: ContentKey, hasIv: bool, iv: seq[byte],
                 data: var seq[byte], scheme: uint32, subs: seq[Subsample],
                 cryptBlocks, skipBlocks: int): DecryptStatus =
  if scheme == esUnencrypted:
    return dsOk
  if not hasKey:
    return dsNoKey
  if not hasIv:
    return dsError

  var ok = false
  let regions = cipherRegions(data.len, subs, ok)
  if not ok:
    return dsError

  if scheme == esCenc:
    # CTR IV may be 8 bytes (Firefox); pad to 16.
    var iv16: seq[byte] = @[]
    for b in iv: iv16.add b
    while iv16.len < 16: iv16.add 0'u8
    if iv16.len != 16: return dsError
    return decryptCenc(key, iv16, data, regions)
  elif scheme == esCbcs:
    if iv.len != 16: return dsError
    return decryptCbcs(key, iv, data, regions, cryptBlocks, skipBlocks)
  else:
    return dsError
