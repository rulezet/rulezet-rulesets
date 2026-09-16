rule sig_20161024_c7285c448b5f64feef119ce53f2bc1c1 {
  meta:
    description = "datamaliciousorder - file 20161024_c7285c448b5f64feef119ce53f2bc1c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0fb50a1a6bbd65c1b4b65387f8b62a60f02e29fbc4760d7a03cc3b7d254c45d"

  strings:
    $s1 = "} while (cy++ < bv);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}