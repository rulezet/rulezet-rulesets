rule Virus_Hijack_Trojan_GenericKDZ_103545_42 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_42.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "878a6a2ed0990ddbd06575b27b0761310bbf04262cd668b0dd8257e45f550d19"

  strings:
    $s1 = "\"4software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}