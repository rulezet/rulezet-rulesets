rule Virus_Hijack_Trojan_GenericKDZ_103545_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc607991a65c67fdf879666726b698556963eb995b1ebde5c1b5943bc39a80c6"

  strings:
    $s1 = "~software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}