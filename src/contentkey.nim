## A decrypted content key, as loaded from a license response.

import util

type
  ContentKey* = object
    id*: seq[byte]          ## key id (may be empty if none was provided)
    hasId*: bool
    data*: seq[byte]        ## the raw (decrypted) key bytes
    keyType*: int           ## License.KeyContainer.KeyType, or -1 if absent
    trackLabel*: string     ## may be empty

proc describe*(k: ContentKey): string =
  ## Hex "id:data [type: label]" — for logging.
  result = ""
  if k.hasId:
    result.add toHex(k.id)
    result.add ":"
  result.add toHex(k.data)
  result.add " ["
  if k.keyType < 0:
    result.add "_"
  else:
    result.add $k.keyType
  if k.trackLabel.len > 0:
    result.add ": \""
    result.add k.trackLabel
    result.add "\""
  result.add "]"
