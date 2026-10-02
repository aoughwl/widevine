## Minimal protobuf (proto2) wire-format codec.
##
## Only the two wire types the Widevine subset uses are supported:
##   0 = varint (int32/int64/uint32/bool/enum)
##   2 = length-delimited (bytes/string/embedded message)
## See docs/PROTO.md for the message/field map. This is deliberately tiny:
## a push-style writer and a pull-style field reader over `seq[byte]`.

type
  ProtoWriter* = object
    buf*: seq[byte]

  ProtoReader* = object
    data: seq[byte]
    pos: int

  WireField* = object
    number*: int        ## field number
    wire*: int          ## wire type (0 or 2)
    u64*: uint64        ## value when wire == 0
    bytesStart*: int    ## slice start when wire == 2
    bytesLen*: int      ## slice length when wire == 2

# ----------------------------------------------------------------- writer ---

proc writeRawVarint(w: var ProtoWriter, v: uint64) =
  var x = v
  while true:
    let b = byte(x and 0x7F'u64)
    x = x shr 7
    if x == 0'u64:
      w.buf.add b
      break
    else:
      w.buf.add (b or 0x80'u8)

proc tag(number, wire: int): uint64 =
  (uint64(number) shl 3) or uint64(wire)

proc putVarint*(w: var ProtoWriter, number: int, value: uint64) =
  ## Encode a wire-type-0 field.
  w.writeRawVarint(tag(number, 0))
  w.writeRawVarint(value)

proc putBool*(w: var ProtoWriter, number: int, value: bool) =
  w.putVarint(number, if value: 1'u64 else: 0'u64)

proc putBytes*(w: var ProtoWriter, number: int, data: seq[byte]) =
  ## Encode a wire-type-2 field from raw bytes.
  w.writeRawVarint(tag(number, 2))
  w.writeRawVarint(uint64(data.len))
  for b in data:
    w.buf.add b

proc putString*(w: var ProtoWriter, number: int, s: string) =
  w.writeRawVarint(tag(number, 2))
  w.writeRawVarint(uint64(s.len))
  for i in 0 ..< s.len:
    w.buf.add byte(s[i])

proc putMessage*(w: var ProtoWriter, number: int, msg: ProtoWriter) =
  ## Embed an already-serialized sub-message.
  w.putBytes(number, msg.buf)

proc finish*(w: ProtoWriter): seq[byte] =
  w.buf

# ----------------------------------------------------------------- reader ---

proc initReader*(data: seq[byte]): ProtoReader =
  ProtoReader(data: data, pos: 0)

proc atEnd*(r: ProtoReader): bool =
  r.pos >= r.data.len

proc readRawVarint(r: var ProtoReader, ok: var bool): uint64 =
  ## Reads a base-128 varint; sets ok=false on truncation/overflow.
  var result0: uint64 = 0
  var shift = 0
  ok = true
  while true:
    if r.pos >= r.data.len or shift >= 64:
      ok = false
      return 0'u64
    let b = r.data[r.pos]
    inc r.pos
    result0 = result0 or (uint64(b and 0x7F'u8) shl shift)
    if (b and 0x80'u8) == 0'u8:
      break
    shift += 7
  result0

proc nextField*(r: var ProtoReader, f: var WireField): bool =
  ## Reads the next field header (+ payload bounds / value). Returns false at
  ## end of buffer or on a malformed/unsupported field.
  if r.atEnd:
    return false
  var ok = false
  let t = r.readRawVarint(ok)
  if not ok:
    return false
  f.number = int(t shr 3)
  f.wire = int(t and 0x7'u64)
  case f.wire
  of 0:
    f.u64 = r.readRawVarint(ok)
    if not ok:
      return false
    f.bytesStart = 0
    f.bytesLen = 0
    return true
  of 2:
    let n = r.readRawVarint(ok)
    if not ok:
      return false
    let length = int(n)
    if r.pos + length > r.data.len:
      return false
    f.bytesStart = r.pos
    f.bytesLen = length
    f.u64 = 0'u64
    r.pos += length
    return true
  else:
    # Wire types 1 (64-bit) and 5 (32-bit) are not used by our schema; we must
    # still skip them if a server sends one, but here we fail closed.
    return false

proc fieldBytes*(r: ProtoReader, f: WireField): seq[byte] =
  ## Copy out a wire-type-2 field's payload.
  result = @[]
  for i in 0 ..< f.bytesLen:
    result.add r.data[f.bytesStart + i]

proc fieldString*(r: ProtoReader, f: WireField): string =
  result = ""
  for i in 0 ..< f.bytesLen:
    result.add char(r.data[f.bytesStart + i])
