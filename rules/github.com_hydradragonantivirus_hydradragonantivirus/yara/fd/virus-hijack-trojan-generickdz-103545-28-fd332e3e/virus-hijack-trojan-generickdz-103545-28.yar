rule Virus_Hijack_Trojan_GenericKDZ_103545_28 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_28.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b59b03bad5d41f17bfa17980e4d25f92f27430b89fd2423aef066f11d3707f3"

  strings:
    $s1 = "\\software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}