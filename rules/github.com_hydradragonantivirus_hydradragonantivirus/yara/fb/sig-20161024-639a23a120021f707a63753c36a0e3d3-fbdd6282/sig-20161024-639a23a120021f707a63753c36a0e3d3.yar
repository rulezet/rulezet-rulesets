rule sig_20161024_639a23a120021f707a63753c36a0e3d3 {
  meta:
    description = "datamaliciousorder - file 20161024_639a23a120021f707a63753c36a0e3d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0b23f8c090abcfe8c888a1db059c95be05720bedc791cdaa0ed07f5ee9688f3"

  strings:
    $s1 = "} while (sd++ < ch);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}