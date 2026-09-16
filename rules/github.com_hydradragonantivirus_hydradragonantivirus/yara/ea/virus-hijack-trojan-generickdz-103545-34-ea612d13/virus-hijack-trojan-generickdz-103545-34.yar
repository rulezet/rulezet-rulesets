rule Virus_Hijack_Trojan_GenericKDZ_103545_34 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_34.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86b11fdb4792bbdec46f6c3371413e2686fa5cb1647d0a15f0338922c2d6b93e"

  strings:
    $s1 = "-software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}