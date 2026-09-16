rule Virus_Hijack_Trojan_GenericKDZ_103545_25 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_25.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e2f598379a63ed6de66d255ca68f2a0f55a399821e1b1a4f14ec993593bf72b"

  strings:
    $s1 = "www.oracle.com/education/oln/index.html, and may be updated by Oracle from time to time with`" fullword ascii
    $s2 = "]software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}