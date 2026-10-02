## Small helpers shared across modules.

proc c_time(t: pointer): int64 {.importc: "time", header: "<time.h>".}

proc nowSeconds*(): int64 =
  ## Seconds since the Unix epoch.
  c_time(cast[pointer](0))

const hexChars = "0123456789abcdef"

proc toHex*(data: seq[byte]): string =
  ## Lowercase hex, no separators.
  result = ""
  for b in data:
    result.add hexChars[int(b shr 4)]
    result.add hexChars[int(b and 0x0F'u8)]

proc bytesEqual*(a, b: seq[byte]): bool =
  if a.len != b.len:
    return false
  for i in 0 ..< a.len:
    if a[i] != b[i]:
      return false
  true

proc toBytes*(s: string): seq[byte] =
  result = @[]
  for i in 0 ..< s.len:
    result.add byte(s[i])
