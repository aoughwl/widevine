## Convert EME init data into a Widevine ContentIdentification (serialized).
## Mirrors openwv's init_data.rs: for CENC we extract the Widevine PSSH payload
## from concatenated ISO-BMFF 'pssh' boxes; for WebM we pass the header through.

import messages, wvcrypto, cdmtypes

type
  InitDataResult* = object
    ok*: bool
    contentId*: seq[byte]    ## serialized ContentIdentification
    unsupported*: bool       ## true => NotSupportedError (vs TypeError)

# Widevine DASH system id: edef8ba9-79d6-4ace-a3c8-27dcd51d21ed
const WidevineSystemId = [
  0xed'u8, 0xef'u8, 0x8b'u8, 0xa9'u8, 0x79'u8, 0xd6'u8, 0x4a'u8, 0xce'u8,
  0xa3'u8, 0xc8'u8, 0x27'u8, 0xdc'u8, 0xd5'u8, 0x1d'u8, 0x21'u8, 0xed'u8]

proc rdU32BE(d: seq[byte], pos: int): uint32 =
  (uint32(d[pos]) shl 24) or (uint32(d[pos+1]) shl 16) or
  (uint32(d[pos+2]) shl 8) or uint32(d[pos+3])

proc rdU64BE(d: seq[byte], pos: int): uint64 =
  var v: uint64 = 0
  for i in 0 ..< 8:
    v = (v shl 8) or uint64(d[pos + i])
  v

proc slice(d: seq[byte], start: int, length: int): seq[byte] =
  result = @[]
  for i in 0 ..< length:
    result.add d[start + i]

## Parse one pssh box payload (the bytes after size+type). Returns (found, data).
proc parsePsshBox(payload: seq[byte], found: var bool): seq[byte] =
  found = false
  result = @[]
  if payload.len < 24:
    return
  if payload[0] != 0'u8:          # only version 0
    return
  for i in 0 ..< 16:
    if payload[4 + i] != WidevineSystemId[i]:
      return
  let dataSize = int(rdU32BE(payload, 20))
  if 24 + dataSize > payload.len:
    return
  found = true
  result = slice(payload, 24, dataSize)

## Scan concatenated 'pssh' boxes for the Widevine one; returns (found, data).
proc parseCenc(boxes: seq[byte], found: var bool): seq[byte] =
  found = false
  result = @[]
  var pos = 0
  while pos < boxes.len:
    if pos + 8 > boxes.len:
      return
    var boxSize = int(rdU32BE(boxes, pos))
    let typeOk = boxes[pos+4] == byte('p') and boxes[pos+5] == byte('s') and
                 boxes[pos+6] == byte('s') and boxes[pos+7] == byte('h')
    var payloadStart = pos + 8
    var payloadEnd: int
    if boxSize == 0:
      payloadEnd = boxes.len
    elif boxSize == 1:
      if pos + 16 > boxes.len:
        return
      boxSize = int(rdU64BE(boxes, pos + 8))
      payloadStart = pos + 16
      payloadEnd = pos + boxSize
    else:
      payloadEnd = pos + boxSize
    if payloadEnd > boxes.len or payloadEnd < payloadStart:
      return
    if typeOk:
      var f = false
      let data = parsePsshBox(slice(boxes, payloadStart, payloadEnd - payloadStart), f)
      if f:
        found = true
        return data
    pos = payloadEnd

proc initDataToContentId*(initDataType: uint32, initData: seq[byte]): InitDataResult =
  result = InitDataResult(ok: false, contentId: @[], unsupported: false)
  let requestId = randomBytes(16)
  if initDataType == idtCenc:
    var found = false
    let psshData = parseCenc(initData, found)
    if not found:
      return                 # NoValidPssh -> TypeError
    result.contentId = encContentIdCenc(psshData, requestId)
    result.ok = true
  elif initDataType == idtWebM:
    result.contentId = encContentIdWebm(initData, requestId)
    result.ok = true
  else:
    result.unsupported = true
