rule sig_20161024_21b9d8820965f8b78bf418d08cee1b4d {
  meta:
    description = "datamaliciousorder - file 20161024_21b9d8820965f8b78bf418d08cee1b4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10528f62d6f3a32fc8d0474a6428a8229a34ed1f708646aac7292b37f4be55e9"

  strings:
    $s1 = "} while (ue++ < nb);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}