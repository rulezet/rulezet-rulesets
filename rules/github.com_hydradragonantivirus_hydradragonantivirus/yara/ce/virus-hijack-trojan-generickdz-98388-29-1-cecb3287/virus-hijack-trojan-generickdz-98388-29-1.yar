rule Virus_Hijack_Trojan_GenericKDZ_98388_29_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9f98b326938bdd7089386eb59fda641950e5f8c1a9ebfd21205f5cc1c97fa98"

  strings:
    $s1 = "TrIed%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}