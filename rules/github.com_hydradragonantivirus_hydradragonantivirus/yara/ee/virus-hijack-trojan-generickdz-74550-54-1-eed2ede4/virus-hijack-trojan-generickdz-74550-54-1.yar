rule Virus_Hijack_Trojan_GenericKDZ_74550_54_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_54_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a11707464de9aa0d7c107ec24afdbbda2c60b914e4561c9e8ae67709d59b3c7"

  strings:
    $s1 = "SHoE;Q" fullword ascii
    $s2 = "6`TSIa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}