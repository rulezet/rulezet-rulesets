rule Virus_Hijack_Trojan_GenericKDZ_98113_29_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b2ab7bc0771bc7c0f3e6e7b6daa835b9928da8dcdbe8c5fd697ae2595588e38"

  strings:
    $s1 = "IV{gizZ" fullword ascii
    $s2 = "lLYN&]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}