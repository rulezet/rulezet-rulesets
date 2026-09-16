rule Virus_Hijack_Trojan_GenericKDZ_98113_225 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_225.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7731021d7b48fe1db6610bc3a7b35bcf94c2d2ae8c76dcabb3c4f96ee5b9aecc"

  strings:
    $s1 = "Rhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}