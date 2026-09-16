rule Trojan_Autorun_Worm_Generic_377591_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Worm.Generic.377591_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7c0d1da3826c271799b0a80323d4371737920b86996ccdede1bc26e9e2a50ca"

  strings:
    $s1 = "-:program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = "-:program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}