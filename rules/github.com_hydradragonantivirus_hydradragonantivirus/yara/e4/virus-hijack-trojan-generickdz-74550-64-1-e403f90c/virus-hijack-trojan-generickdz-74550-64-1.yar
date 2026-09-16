rule Virus_Hijack_Trojan_GenericKDZ_74550_64_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_64_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db584935d8ac1512bebdd60ae2758bccae94663acf19a2bf1a62145b5318e2d6"

  strings:
    $s1 = "+`Sark" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}