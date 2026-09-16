rule Virus_Hijack_Trojan_GenericKDZ_74550_114_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_114_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1003687efca247ba60bb37bb15b44f9d97f255acb3cb85b2a9f9929378d2fadc"

  strings:
    $s1 = ">Oh[maLT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}