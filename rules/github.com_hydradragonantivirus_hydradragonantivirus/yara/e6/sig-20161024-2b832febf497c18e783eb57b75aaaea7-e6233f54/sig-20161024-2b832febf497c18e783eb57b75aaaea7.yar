rule sig_20161024_2b832febf497c18e783eb57b75aaaea7 {
  meta:
    description = "datamaliciousorder - file 20161024_2b832febf497c18e783eb57b75aaaea7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f3fe7cb9313988d337b8b71b400dbfe5f2e81fdba4ebf949fef91f171f17bca"

  strings:
    $s1 = "} while (os++ < es);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}