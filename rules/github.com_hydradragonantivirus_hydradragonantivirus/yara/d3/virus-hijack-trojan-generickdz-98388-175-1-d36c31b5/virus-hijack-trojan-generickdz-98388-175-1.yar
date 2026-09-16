rule Virus_Hijack_Trojan_GenericKDZ_98388_175_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_175_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b2832f861286d771b8e41b7ccaaf958ecda04467055af663ff6ea07b955a798"

  strings:
    $s1 = "A<proa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}