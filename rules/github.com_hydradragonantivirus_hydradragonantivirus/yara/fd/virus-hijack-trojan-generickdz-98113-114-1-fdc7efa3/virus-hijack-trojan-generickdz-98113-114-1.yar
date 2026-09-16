rule Virus_Hijack_Trojan_GenericKDZ_98113_114_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_114_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "847ff52fc9cd7a398ff2b3a556a4680bdd44d1a910331d3e3f2950b60ff4a518"

  strings:
    $s1 = "fisH*z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}