import nimcrypt/[crypt]
import std/unittest, std/times

suite "Unix crypt tests":
  const
    md5Hello = [
      "$1$saltstring",
      "Hello world!",
      "$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1"
    ]

    md5HelloLongerSalt = [
      "$1$saltstringsaltstring",
      "Hello world!",
      "$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1"
    ]

    md5LongerText = [
      "$1$anotherlongsaltstring",
      """a very much longer text to encrypt.  This one even stretches over morethan one line.""",
      "$1$anotherl$K6Vw1g4o5xCrk48TD5civ."
    ]

    sha256Hello = [
      "$5$saltstring",
      "Hello world!",
      "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"
    ]

    sha256Hello1000Rounds = [
      "$5$rounds=10000$saltstringsaltstring",
      "Hello world!",
      "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"
    ]

    sha256SaltTooLong = [
      "$5$rounds=5000$toolongsaltstring",
      "This is just a test",
      "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5"
    ]

    sha256LongerText = [
      "$5$rounds=1400$anotherlongsaltstring",
      """a very much longer text to encrypt.  This one even stretches over morethan one line.""",
      "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1"
    ]

    sha256ShortSalt = [
      "$5$rounds=77777$short",
      "we have a short salt string but not a short password",
      "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/"
    ]

    sha256LongSalt = [
      "$5$rounds=123456$asaltof16chars..",
      "a short string",
      "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD"
    ]

    sha256RoundsTooLow = [
      "$5$rounds=10$roundstoolow",
      "the minimum number is still observed",
      "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC"
    ]

    sha512Hello = [
      "$6$saltstring",
      "Hello world!",
      "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
    ]

    sha512Hello1000Rounds = [
      "$6$rounds=10000$saltstringsaltstring",
      "Hello world!",
      "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."
    ]

    sha512SaltTooLong = [
      "$6$rounds=5000$toolongsaltstring",
      "This is just a test",
      "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"
    ]

    sha512LongerText = [
      "$6$rounds=1400$anotherlongsaltstring",
      """a very much longer text to encrypt.  This one even stretches over morethan one line.""",
      "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1"
    ]

    sha512ShortSalt = [
      "$6$rounds=77777$short",
      "we have a short salt string but not a short password",
      "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"
    ]

    sha512LongSalt = [
      "$6$rounds=123456$asaltof16chars..",
      "a short string",
      "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"
    ]

    sha512RoundsTooLow = [
      "$6$rounds=10$roundstoolow",
      "the minimum number is still observed",
      "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."
    ]

  test "crypt MD5 tests":
    check:
      crypt(md5Hello[1], md5Hello[0]) ==  md5Hello[2]
      crypt(md5HelloLongerSalt[1], md5HelloLongerSalt[0]) == md5HelloLongerSalt[2]
      crypt(md5LongerText[1], md5LongerText[0]) == md5LongerText[2]

  test "crypt SHA-256 tests":
    check:
      crypt(sha256Hello[1], sha256Hello[0]) ==  sha256Hello[2]
      crypt(sha256Hello1000Rounds[1], sha256Hello1000Rounds[0]) == sha256Hello1000Rounds[2]
      crypt(sha256SaltTooLong[1], sha256SaltTooLong[0]) == sha256SaltTooLong[2]
      crypt(sha256LongerText[1], sha256LongerText[0]) == sha256LongerText[2]
      crypt(sha256ShortSalt[1], sha256ShortSalt[0]) == sha256ShortSalt[2]
      crypt(sha256LongSalt[1], sha256LongSalt[0]) == sha256LongSalt[2]
      crypt(sha256RoundsTooLow[1], sha256RoundsTooLow[0]) == sha256RoundsTooLow[2]

  test "crypt SHA-512 tests":
    check:
      crypt(sha512Hello[1], sha512Hello[0]) ==  sha512Hello[2]
      crypt(sha512Hello1000Rounds[1], sha512Hello1000Rounds[0]) == sha512Hello1000Rounds[2]
      crypt(sha512SaltTooLong[1], sha512SaltTooLong[0]) == sha512SaltTooLong[2]
      crypt(sha512LongerText[1], sha512LongerText[0]) == sha512LongerText[2]
      crypt(sha512ShortSalt[1], sha512ShortSalt[0]) == sha512ShortSalt[2]
      crypt(sha512LongSalt[1], sha512LongSalt[0]) == sha512LongSalt[2]
      crypt(sha512RoundsTooLow[1], sha512RoundsTooLow[0]) == sha512RoundsTooLow[2]

  test "verify MD5 tests":
    check:
      verify(md5Hello[2], md5Hello[1])
      verify(md5HelloLongerSalt[2], md5HelloLongerSalt[1])
      verify(md5LongerText[2], md5Hello[1]) == false
      verify(md5LongerText[2], md5LongerText[1])

  test "verify SHA-256 tests":
    var truncatedHash = sha256LongSalt[2].substr(0, sha256LongSalt[2].high - 1)
    check:
      verify(sha256Hello[2], sha256Hello[1])
      verify(sha256Hello1000Rounds[2], sha256Hello1000Rounds[1])
      verify(sha256Hello1000Rounds[2], sha256Hello[1])
      verify(sha256RoundsTooLow[2], sha256RoundsTooLow[1])
      verify(sha256LongSalt[2], sha256LongSalt[1]) != verify(truncatedHash, sha256LongSalt[1])

  test "verify SHA-512 tests":
    check:
      verify(sha512Hello[2], sha512Hello[1])
      verify(sha512RoundsTooLow[2], sha512RoundsTooLow[1])
      verify(sha512RoundsTooLow[0], sha512RoundsTooLow[1]) == verify("$6$rounds=1000$roundstoolow", sha512RoundsTooLow[1])
