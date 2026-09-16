rule Virus_Hijack_Trojan_GenericKDZ_103545_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e45e3d87f609750f8728cca77800d1e97ddfe35595cc5b7c37752c366d99b2c"

  strings:
    $s1 = "msoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}