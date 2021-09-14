## Unix crypt implementation following Dreller's description at http://www.akkadia.org/drepper/SHA-crypt.txt

#[
  copyright (c) 2021, Florent Heyworth

  A nim implementation of the Unix C library crypt function with support for
  MD5, SHA-256 and SHA-512 algorithms. The library uses the [nimcrypt](https://github.com/cheatfate/nimcrypto) library
  for the SHA hash family

  The SHA-256 and SHA-512 implementations follow Drepper's implementation
  as described under http://www.akkadia.org/drepper/SHA-crypt.txt
]#

import std/base64, std/strformat, std/strutils, std/md5, std/bitops, nimcrypto

const USE_MD5* = "$1$"
const USE_SHA256* = "$5$"
const USE_SHA512* = "$6$"
const DEFAULT_PREFIX* = USE_SHA512
const MAX_SALT_LENGTH* = 16
const DEFAULT_ROUNDS* = 5000
const ROUNDS_PREFIX = "rounds="
const MIN_ROUNDS = 1000
const MAX_ROUNDS = 999999999
const B64_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

type
  CryptRound = object
    num: int
    explicit: bool
  SaltConfig = object
    rounds: CryptRound
    salt: string
    prefix: string
    saltLen: int

template hygienic(body: untyped) =
  when not defined(noScrub):
    body

func strcspn(left: string, right: string): int =
  var loc = 0
  for x in left:
    loc += 1
    for y in right:
      if x == y:
        return loc
  len(left)

proc nonZeroRandomBytes(length: int): string =
  result = newString(length)

  if randomBytes(addr(result[0]), length) != length:
    raise newException(Defect, "Failed to generate enough random bytes")

  for i in countup(0, length - 1):
    while result[i] == '\0':
      if randomBytes(addr(result[i]), 1) != 1:
        raise newException(Defect, "Failed to generate enough random bytes")

proc makeSalt*(prefix: string = "$6$", rounds: int = 5000, saltLen = 16): string =
  ## Generates a random salt - the following prefixes are currently supported
  ##  - `$1$`: MD5
  ##  - `$5$`: SHA-256
  ##  - `$6$`: SHA-512
  ##
  ## Note: MAX_SALT_LENGTH is defined as 16 for compatibility with https://www.akkadia.org/drepper/SHA-crypt.txt
  var saltLength = if saltLen <= MAX_SALT_LENGTH: saltLen else: MAX_SALT_LENGTH
  let bytes = nonZeroRandomBytes(saltLength)

  var roundSpecification = ""
  if prefix != USE_MD5 and rounds != DEFAULT_ROUNDS:
    roundSpecification = &"{ROUNDS_PREFIX}{rounds}$"
  &"{prefix}{roundSpecification}{encode(bytes)}"

func copyTo(bytes: openArray[byte|uint8], buffer: var string) =
  let length = bytes.len
  if length > 0:
    copyMem(buffer.cstring, bytes[0].unsafeAddr, length)

func b64(b2: uint, b1: uint, b0: uint, length: int, buffer: var string, pos: var int) =
  var entry = (b2 shl 16) or (b1 shl 8) or b0
  var vLen = length
  while true:
    if vLen <= 0:
      break
    vLen -= 1
    buffer[pos] = B64_CHARS[(entry and 0x3f)]
    pos += 1
    entry = entry shr 6

func getRounds(incantation: string): int =
  var rounds = ""
  for ch in incantation:
    if ch.isDigit():
      rounds &= ch
    else:
      break
  parseInt(rounds)

func parseSalt(salt: string): SaltConfig =
  var realSalt = salt
  var rounds: int = DEFAULT_ROUNDS

  if len(salt) < 4:
    raise newException(Defect, "Salt too short")
  let prefix = salt.substr(0, 2)
  if not prefix.startsWith("$") or not prefix.endsWith("$"):
    raise newException(Defect, &"Unknown algorithm {prefix}")
  let rPos = realSalt.find(ROUNDS_PREFIX)
  if rPos != - 1:
    if prefix != USE_MD5:
      rounds = getRounds(realSalt.substr(rPos + ROUNDS_PREFIX.len))
      realSalt = replace(realSalt, ROUNDS_PREFIX & $rounds & "$", "")
      if rounds < MIN_ROUNDS:
        rounds = MIN_ROUNDS
      elif rounds > MAX_ROUNDS:
        rounds = MAX_ROUNDS

  if realSalt.startsWith(prefix):
    realSalt = realSalt.substr(prefix.len)

  let maxSaltLen = if prefix == USE_MD5: 8 else: MAX_SALT_LENGTH
  let saltLen = min(strcspn(realSalt, "$"), maxSaltLen)
  if saltLen < realSalt.len:
      realSalt = realSalt.substr(0, saltLen - 1)

  result.rounds = CryptRound(num: rounds, explicit: rPos != -1)
  result.salt = realSalt
  result.saltLen = saltLen
  result.prefix = prefix

func compute(ctx: MD5Context, altDigest: MD5Digest): string =
  var buffer = newString(22)
  var pos = 0
  b64(altDigest[0], altDigest[6], altDigest[12], 4, buffer, pos)
  b64(altDigest[1], altDigest[7], altDigest[13], 4, buffer, pos)
  b64(altDigest[2], altDigest[8], altDigest[14], 4, buffer, pos)
  b64(altDigest[3], altDigest[9], altDigest[15], 4, buffer, pos)
  b64(altDigest[4], altDigest[10], altDigest[5], 4, buffer, pos)
  b64(0, 0, altDigest[11], 2, buffer, pos)
  buffer

func compute(ctx: sha256, altDigest: MDigest): string =
  var buffer = newString(ctx.sizeDigest + 11)
  var pos = 0
  b64(altDigest.data[0], altDigest.data[10], altDigest.data[20], 4, buffer, pos)
  b64(altDigest.data[21], altDigest.data[1], altDigest.data[11], 4, buffer, pos)
  b64(altDigest.data[12], altDigest.data[22], altDigest.data[2], 4, buffer, pos)
  b64(altDigest.data[3], altDigest.data[13], altDigest.data[23], 4, buffer, pos)
  b64(altDigest.data[24], altDigest.data[4], altDigest.data[14], 4, buffer, pos)
  b64(altDigest.data[15], altDigest.data[25], altDigest.data[5], 4, buffer, pos)
  b64(altDigest.data[6], altDigest.data[16], altDigest.data[26], 4, buffer, pos)
  b64(altDigest.data[27], altDigest.data[7], altDigest.data[17], 4, buffer, pos)
  b64(altDigest.data[18], altDigest.data[28], altDigest.data[8], 4, buffer, pos)
  b64(altDigest.data[9], altDigest.data[19], altDigest.data[29], 4, buffer, pos)
  b64(0, altDigest.data[31], altDigest.data[30], 3, buffer, pos)
  buffer

func compute(ctx: sha512, altDigest: MDigest): string =
  var buffer = newString(ctx.sizeDigest + 22)
  var pos = 0
  b64(altDigest.data[0], altDigest.data[21], altDigest.data[42], 4, buffer, pos)
  b64(altDigest.data[22], altDigest.data[43], altDigest.data[1], 4, buffer, pos)
  b64(altDigest.data[44], altDigest.data[2], altDigest.data[23], 4, buffer, pos)
  b64(altDigest.data[3], altDigest.data[24], altDigest.data[45], 4, buffer, pos)
  b64(altDigest.data[25], altDigest.data[46], altDigest.data[4], 4, buffer, pos)
  b64(altDigest.data[47], altDigest.data[5], altDigest.data[26], 4, buffer, pos)
  b64(altDigest.data[6], altDigest.data[27], altDigest.data[48], 4, buffer, pos)
  b64(altDigest.data[28], altDigest.data[49], altDigest.data[7], 4, buffer, pos)
  b64(altDigest.data[50], altDigest.data[8], altDigest.data[29], 4, buffer, pos)
  b64(altDigest.data[9], altDigest.data[30], altDigest.data[51], 4, buffer, pos)
  b64(altDigest.data[31], altDigest.data[52], altDigest.data[10], 4, buffer, pos)
  b64(altDigest.data[53], altDigest.data[11], altDigest.data[32], 4, buffer, pos)
  b64(altDigest.data[12], altDigest.data[33], altDigest.data[54], 4, buffer, pos)
  b64(altDigest.data[34], altDigest.data[55], altDigest.data[13], 4, buffer, pos)
  b64(altDigest.data[56], altDigest.data[14], altDigest.data[35], 4, buffer, pos)
  b64(altDigest.data[15], altDigest.data[36], altDigest.data[57], 4, buffer, pos)
  b64(altDigest.data[37], altDigest.data[58], altDigest.data[16], 4, buffer, pos)
  b64(altDigest.data[59], altDigest.data[17], altDigest.data[38], 4, buffer, pos)
  b64(altDigest.data[18], altDigest.data[39], altDigest.data[60], 4, buffer, pos)
  b64(altDigest.data[40], altDigest.data[61], altDigest.data[19], 4, buffer, pos)
  b64(altDigest.data[62], altDigest.data[20], altDigest.data[41], 4, buffer, pos)
  b64(0, 0, altDigest.data[63], 2, buffer, pos)
  buffer

func md5Crypt(md5Ctx: var MD5Context, key: string, salt: string): string =
  let
    keyLen = len(key)
    config = parseSalt(salt)
    saltLen = config.saltLen
  var
    altDigest: MD5Digest
    altCtx: MD5Context
    digestBuffer = newString(sizeof MD5Digest)
    realSalt = config.salt

  md5Init(md5Ctx)
  md5Init(altCtx)

  md5Update(md5Ctx, key, keyLen)
  md5Update(md5Ctx, USE_MD5, USE_MD5.len)
  md5Update(md5Ctx, realSalt, saltLen)
  md5Update(altCtx, key, keyLen)
  md5Update(altCtx, realSalt, saltLen)
  md5Update(altCtx, key, keyLen)
  md5Final(altCtx, altDigest)

  altDigest.copyTo(digestBuffer)
  var counter = keyLen
  while counter - 16 > 0:
    md5Update(md5Ctx, digestBuffer, 16)
    counter -= 16
  md5Update(md5Ctx, digestBuffer, counter)

  altDigest[0] = 0
  altDigest.copyTo(digestBuffer)
  counter = keyLen
  while counter > 0:
    md5Update(md5Ctx, if (counter and 1) != 0: digestBuffer else: key, 1)
    counter = counter shr 1
  md5Final(md5Ctx, altDigest)

  for i in countup(0, MIN_ROUNDS - 1):
    md5Init(md5Ctx)
    altDigest.copyTo(digestBuffer)
    if (i and 1) != 0:
      md5Update(md5Ctx, key, keyLen)
    else:
      md5Update(md5Ctx, digestBuffer, 16)
    if (i mod 3) != 0:
      md5Update(md5Ctx, realSalt, saltLen)
    if (i mod 7) != 0:
      md5Update(md5Ctx, key, keyLen)
    if (i and 1) != 0:
      md5Update(md5Ctx, digestBuffer, 16)
    else:
      md5Update(md5Ctx, key, keyLen)
    md5Final(md5Ctx, altDigest)

  var buffer = md5Ctx.compute(altDigest)
  hygienic:
    md5Init(md5Ctx)
    md5Final(md5Ctx, altDigest)
    md5Init(altCtx)
    zeroMem(addr(digestBuffer[0]), len(digestBuffer))
  &"{USE_MD5}{realSalt}${buffer}"

func shaCrypt[T=Sha2Context](shaCtx: var T, pass: string, salt: string): string =
  let
    keyLen = len(pass)
    config = parseSalt(salt)
    prefix = config.prefix
    saltLen = config.saltLen
    rounds = config.rounds.num
    sizeDigest = shaCtx.sizeDigest
    sizeInc = int(shaCtx.sizeDigest)
  var
    altCtx: T
    key = pass
    realSalt = config.salt

  init(shaCtx)
  init(altCtx)

  update(shaCtx, cast[ptr uint8](addr(key[0])), uint(keyLen))
  update(shaCtx, cast[ptr uint8](addr(realSalt[0])), uint(saltLen))
  update(altCtx, cast[ptr uint8](addr(key[0])), uint(keyLen))
  update(altCtx, cast[ptr uint8](addr(realSalt[0])), uint(saltLen))
  update(altCtx, cast[ptr uint8](addr(key[0])), uint(keyLen))
  var altDigest = finish(altCtx)

  var counter = keyLen
  while counter - sizeInc > 0:
    update(shaCtx, addr(altDigest.data[0]), sizeDigest)
    counter -= sizeInc
  update(shaCtx, addr(altDigest.data[0]), uint(counter))

  counter = keyLen
  while counter > 0:
    if (counter and 1) != 0:
      update(shaCtx, addr(altDigest.data[0]), sizeDigest)
    else:
      update(shaCtx, cast[ptr uint8](addr(key[0])), uint(keyLen))
    counter = counter shr 1
  altDigest = finish(shaCtx)

  init(altCtx)
  for i in 0 ..< keyLen:
    update(altCtx, cast[ptr uint8](addr(key[0])), uint(keyLen))
  var tempResult = finish(altCtx)

  var pBytes: seq[byte] = newSeq[byte](keyLen)
  counter = keyLen
  var offset = 1
  while counter - sizeInc > 0:
    copyMem(addr(pBytes[offset - 1]), addr(tempResult.data[0]), sizeDigest)
    counter -= sizeInc
    offset += sizeInc
  copyMem(addr(pBytes[offset - 1]), addr(tempResult.data[0]), counter)

  init(altCtx)
  var upTo = 16 + cint(altDigest.data[0])
  var i = 0
  while i < upTo:
    update(altCtx, cast[ptr uint8](addr(realSalt[0])), uint(saltLen))
    i += 1
  tempResult = finish(altCtx)

  counter = saltLen
  var sBytes: seq[byte] = newSeq[byte](saltLen)
  offset = 1
  while counter - sizeInc >= sizeInc:
    copyMem(addr(sBytes[offset - 1]), addr(tempResult.data[0]), sizeDigest)
    counter -= sizeInc
    offset += sizeInc
  copyMem(addr(sBytes[offset - 1]), addr(tempResult.data[0]), counter)

  for i in countup(0, rounds - 1):
    init(shaCtx)
    if (i and 1) != 0:
      update(shaCtx,  addr(pBytes[0]), uint(keyLen))
    else:
      update(shaCtx, addr(altDigest.data[0]), sizeDigest)
    if (i mod 3) != 0:
      update(shaCtx, addr(sBytes[0]), uint(saltLen))
    if (i mod 7) != 0:
      update(shaCtx, addr(pBytes[0]), uint(keyLen))
    if (i and 1) != 0:
      update(shaCtx, addr(altDigest.data[0]), sizeDigest)
    else:
      update(shaCtx, addr(pBytes[0]), uint(keyLen))
    altDigest = finish(shaCtx)

  var buffer = shaCtx.compute(altDigest)
  var roundsSpecification = ""
  if rounds != DEFAULT_ROUNDS or config.rounds.explicit:
    roundsSpecification = &"{ROUNDS_PREFIX}{rounds}$"

  hygienic:
    init(shaCtx)
    altDigest = finish(shaCtx)
    init(altCtx)
    tempResult = finish(altCtx)
    zeroMem(addr(pBytes[0]), len(pBytes))
    zeroMem(addr(sBytes[0]), len(sBytes))
  &"{prefix}{roundsSpecification}{realSalt}${buffer}"

func constantTimeEquals(left: string, right: string): bool =
  if len(left) != len(right):
    return false
  var bitDiffs = 0
  for i in 0 ..< len(left):
    bitDiffs = bitor(bitDiffs, (int(uint8(left[i])) xor int(uint8(right[i]))))
  bitDiffs == 0

func hashPart(hash: string): string =
  let pos = rfind(hash, "$")
  if pos != -1 and pos < hash.len:
    return hash.substr(pos + 1)
  hash

func crypt*(password: string, salt: string): string =
  ## The salt is composed of three parts:
  ##  - part 1: dollar-terminated algorithm - currently `$1$` (MD5), `$5$` (SHA256) and `$6$` (SHA512) are supported
  ##  - part 2: optional dollar-terminated rounds specification `rounds=<number>`. Not used in MD5, defaults to 5000 for SHA hashes
  ##  - part 3: actual salt
  ## Example:
  ##    `$6$rounds=10000$myactualsalt`
  ##
  ## Recommendation: use the `makeSalt` function to generate random salts
  if salt.startsWith(USE_MD5):
    var ctx: MD5Context
    return md5Crypt(ctx, password, salt)
  if salt.startsWith(USE_SHA256):
    var ctx: sha256
    return shaCrypt[sha256](ctx, password, salt)
  if salt.startsWith(USE_SHA512):
    var ctx: sha512
    return shaCrypt[sha512](ctx, password, salt)

  raise newException(Defect, "Unsupported algorithm")

func verify*(hash: string, password: string): bool =
  ## Returns true if password produces an identical hash
  let config = parseSalt(hash)
  let rounds = if config.rounds.explicit: &"{ROUNDS_PREFIX}{config.rounds.num}$" else: ""
  let saltPart = config.salt.strip(false, true, {'$'})
  let salt = &"{config.prefix}{rounds}{saltPart}"
  let verhash = crypt(password, salt)
  constantTimeEquals(hashPart(hash), hashPart(verhash))