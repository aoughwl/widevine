## Parse a pywidevine `.wvd` device identity. Layout (see docs/ALGORITHMS.md):
##   "WVD" | version:u8 | type:u8 | security_level:u8 | flags:u8
##   priv_key_len:u16be | priv_key(PKCS#1 DER)
##   client_id_len:u16be | client_id(serialized ClientIdentification)
##   [v1 only: vmp_len:u16be | vmp]   (ignored)
## The private key and client id are kept as opaque bytes.

type
  WidevineDevice* = object
    privateKey*: seq[byte]   ## PKCS#1 DER RSA private key
    clientId*: seq[byte]     ## serialized ClientIdentification (opaque)

proc rdU16BE(data: seq[byte], pos: int): int =
  (int(data[pos]) shl 8) or int(data[pos + 1])

proc parseWvd*(data: seq[byte], dev: var WidevineDevice): bool =
  ## Returns true and fills `dev` on success.
  dev = WidevineDevice(privateKey: @[], clientId: @[])
  if data.len < 7:
    return false
  if data[0] != byte('W') or data[1] != byte('V') or data[2] != byte('D'):
    return false
  let version = data[3]
  if version != 1'u8 and version != 2'u8:
    return false
  # data[4]=type, data[5]=security_level, data[6]=flags  (unused)
  var pos = 7
  if pos + 2 > data.len:
    return false
  let pkLen = rdU16BE(data, pos)
  pos += 2
  if pos + pkLen > data.len:
    return false
  var pk: seq[byte] = @[]
  for i in 0 ..< pkLen:
    pk.add data[pos + i]
  pos += pkLen

  if pos + 2 > data.len:
    return false
  let cidLen = rdU16BE(data, pos)
  pos += 2
  if pos + cidLen > data.len:
    return false
  var cid: seq[byte] = @[]
  for i in 0 ..< cidLen:
    cid.add data[pos + i]

  dev = WidevineDevice(privateKey: pk, clientId: cid)
  true
