rule Virus_Hijack_Trojan_GenericKDZ_98113_259_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_259_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2a62335a3dd6d17ebfc709d8ddf4876acc42764abba5be9c8047d778707c2bb"

  strings:
    $s1 = "$Pram.:" fullword ascii
    $s2 = ":Name;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}