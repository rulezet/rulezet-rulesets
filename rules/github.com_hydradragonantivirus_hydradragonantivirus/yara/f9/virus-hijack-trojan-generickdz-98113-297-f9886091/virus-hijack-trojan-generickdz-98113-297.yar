rule Virus_Hijack_Trojan_GenericKDZ_98113_297 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_297.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c606703c9abfa54ed3d43d8d2250001640edc8b8f5b9c614ff19e6852e0eaa80"

  strings:
    $s1 = "WOby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}