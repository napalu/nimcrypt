# Package

version       = "1.0.1"
author        = "Florent Heyworth"
description   = "Nim implementation of MD5, SHA-256 and SHA-512 Unix crypt"
license       = "MIT"
skipDirs      = @["tests", "docs"]



# Dependencies
requires "nim >= 1.2.0", "nimcrypto >= 0.5.4", "checksums"

# Tests
task test, "Runs the test suite":
  var testBase = @[
    "nim c -f -r tests/",
    "nim c -f -d:danger -r tests/"
  ]

  for test in testBase:
    echo "\n" & test & "testcrypt"
    exec test & "testcrypt"
    rmFile("tests/testcrypt".toExe())
