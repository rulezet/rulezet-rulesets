rule Virus_Hijack_Trojan_GenericKDZ_79663_23_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24b4c7d4ae11ace6f92aee71a670d85aaec2a8c57a7f7cb18ceff8b3c07ed8fc"

  strings:
    $s1 = "8L,{oRlO" fullword ascii
    $s2 = "z%maNt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}