rule Virus_Hijack_Trojan_GenericKDZ_99416_38 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_38.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd31e4116ed8b38860bfe0e2585d0cf049a48a4ad48c4fb1f0ecec860781df0e"

  strings:
    $s1 = ".dUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}