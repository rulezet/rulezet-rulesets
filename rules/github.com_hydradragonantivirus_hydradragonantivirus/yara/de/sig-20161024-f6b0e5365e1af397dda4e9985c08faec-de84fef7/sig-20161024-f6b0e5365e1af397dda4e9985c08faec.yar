rule sig_20161024_f6b0e5365e1af397dda4e9985c08faec {
  meta:
    description = "datamaliciousorder - file 20161024_f6b0e5365e1af397dda4e9985c08faec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8424fc112a149f4a52104829c4038d430af2a434730c6c816ae759abc080e82c"

  strings:
    $s1 = "} while (yx++ < cs);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}