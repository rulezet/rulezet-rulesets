rule Virus_Hijack_Trojan_GenericKDZ_74550_149_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_149_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2db90cd4bfffa8678c31dd69c8e2b2f0d8fff0cf3a615ccf8003b5539015688a"

  strings:
    $s1 = "P+<KOzO" fullword ascii
    $s2 = "lZf bADE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}