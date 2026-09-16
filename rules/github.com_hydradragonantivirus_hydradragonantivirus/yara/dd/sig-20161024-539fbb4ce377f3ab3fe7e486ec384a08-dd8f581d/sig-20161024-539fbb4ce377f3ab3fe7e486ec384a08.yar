rule sig_20161024_539fbb4ce377f3ab3fe7e486ec384a08 {
  meta:
    description = "datamaliciousorder - file 20161024_539fbb4ce377f3ab3fe7e486ec384a08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3659522cb82555f10f09b0d2de542a7916b0a247894dc2b723eb35f34ebdc36"

  strings:
    $s1 = "} while (rr++ < qx);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}