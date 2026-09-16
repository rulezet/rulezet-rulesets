rule Virus_Hijack_Trojan_GenericKDZ_99416_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9d47eaa3368f66c6d6b37ef8b81b08f4fd68415b453e746f1ce984d4cd5598e"

  strings:
    $s1 = "m]<@FAon" fullword ascii
    $s2 = "wain[n" fullword ascii
    $s3 = "q]Toll " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}