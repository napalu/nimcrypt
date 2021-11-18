# nimcrypt

# Unix crypt implementation

A nim implementation of the Unix library crypt functionality with support for
MD5, SHA-256 and SHA-512 algorithms. Depends on the [nimcrypto](https://github.com/cheatfate/nimcrypto) library
for the SHA hash implementations.

The crypt SHA-256 and SHA-512 functionality follow Drepper's implementation as described under
http://www.akkadia.org/drepper/SHA-crypt.txt

By default, the encryption contexts and buffers are invalidated/zeroed out after each crypt() call.
You can opt out of this hygiene by compiling with -d:noScrub

## Usage

```bash
# install
nimble install nimcrypt
```

```bash
# run tests
nimble test
```

```nim
# example-sha256.nim
import nimcrypt

var pass = "Crypt me"

# crypt SHA-256
salt = "$5$myspecialsalt"
echo crypt(pass, salt)
# outputs $5$myspecialsalt$xbN1ICMrxrACrd1Kb4Hj7aW7IsdGetrRIOGGdDDjcS1

# crypt SHA-256 with custom rounds (defaults to 5000 rounds)
salt = "$5$rounds=10000$myspecialsalt"
echo crypt(pass, salt)
# outputs $5$rounds=10000$myspecialsalt$HXVz4e..zb96e5QJIObcvGL5cDzMqnWsGp/h7f68cGA
```
```nim
# example-sha512.nim
import nimcrypt

var pass = "Crypt me"
# crypt SHA-512
var salt = "$6$myspecialsalt"
echo crypt(pass, salt)
# outputs $6$myspecialsalt$JlMpgU2NQNZbf1B7q4/SsC1wfXviYDmx.QxxsldFfL88qC3bqMMNnCgGB38RbawMx3aXV99ym0IxNDo20Rkcy1

# crypt SHA-512 with custom rounds (defaults to 5000 rounds)
salt = "$6$rounds=10000$myspecialsalt"
echo crypt(pass, salt)
#outputs $6$rounds=10000$myspecialsalt$NM5gIDUNPfKhL18Qp3rk8Upv9IsUfy4xMNs3yrvNUaVWzVXLT1277ZX1lH6yHokRNuPY6cuzgQBBw6kh76iOa0
```

```nim
# example-md5.nim
import nimcrypt

var pass = "Crypt me"

# crypt MD5
var salt = "$1$myspecialsalt"
echo crypt(pass, salt)
# outputs $1$myspecia$On9Tdyuip8kmj9qgryK9M. 

# caution: as per specification, MD5 rounds are fixed. If you specify a `rounds` param it will be used as salt
salt = "$1$rounds=10000$myspecialsalt"
echo crypt(pass, salt)
# outputs $1$rounds=1$NcYlc.WQ5KrlZPQbugaQy0
```

```nim
# example-verify.nim
import nimcrypt

var pass = "Crypt me"
var hash = "$1$myspecia$On9Tdyuip8kmj9qgryK9M"
echo verify(hash, pass)
# outputs true
```

```nim
# example-with-random-salts.nim

# crypt with random SHA-512 salt
echo crypt(pass, makeSalt("$6$"))
# crypt with random SHA-512 salt with custom rounds 
echo crypt(pass, makeSalt("$6$", 10000))
# crypt with random SHA-256 salt
echo crypt(pass, makeSalt("$5$"))
# crypt with random SHA-256 salt with custom rounds 
echo crypt(pass, makeSalt("$5$", 10000))
# crypt with random MD5 salt (custom rounds are ignored)
echo crypt(pass, makeSalt("$1$"))
```
