rule sig_20161024_59437fd57e29a7030b7914e48e9499ac {
  meta:
    description = "datamaliciousorder - file 20161024_59437fd57e29a7030b7914e48e9499ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03d129704b3b1d4400e5a73dab034c3beab414464c08a869969b8b6db3982ff5"

  strings:
    $s1 = "} while (ve++ < gd);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}