rule sig_20161024_9054955f3a375be8ae8c29042eeccdc9 {
  meta:
    description = "datamaliciousorder - file 20161024_9054955f3a375be8ae8c29042eeccdc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ee5d1a52296a3b332ee4f38166883415c46fca514a820ed8cc723232af3c4fc"

  strings:
    $s1 = "} while (dq0++ < no0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}