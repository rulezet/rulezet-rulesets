rule sig_20161024_0804ca5d90f12a196225f40954f367c8 {
  meta:
    description = "datamaliciousorder - file 20161024_0804ca5d90f12a196225f40954f367c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41508194db2956ec31bb97bb0f3b6361be6f95351e5e9c789c9c788fd2a58af3"

  strings:
    $s1 = "} while (in0++ < es);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}