rule Virus_Hijack_Trojan_GenericKDZ_105924_331_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_331_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b81b945f8de674a48ddb9e3ec258e4cdf47ff5e8c0aa66ced73057ef46366323"

  strings:
    $s1 = "glEn,#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}