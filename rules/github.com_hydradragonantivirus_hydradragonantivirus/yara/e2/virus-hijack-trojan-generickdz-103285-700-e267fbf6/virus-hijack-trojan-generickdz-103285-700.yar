rule Virus_Hijack_Trojan_GenericKDZ_103285_700 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_700.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca9be99d49258769125dbfc598143db760b3ea1910f462a05083b9d3f8968593"

  strings:
    $s1 = ";NEXT*EY<AD0>)EXj" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}