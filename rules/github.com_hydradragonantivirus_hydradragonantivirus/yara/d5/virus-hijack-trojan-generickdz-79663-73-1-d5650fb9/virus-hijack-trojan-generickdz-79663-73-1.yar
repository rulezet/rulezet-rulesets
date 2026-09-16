rule Virus_Hijack_Trojan_GenericKDZ_79663_73_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_73_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b554e3d51573b1fc6bf61d2f5f176fd6dbeb94bc81f82d24166d1129043c92ae"

  strings:
    $s1 = "A.&kIte" fullword ascii
    $s2 = "T)OrAD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}