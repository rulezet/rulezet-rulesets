rule Virus_Danger_Trojan_GenericKDZ_103545 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103545.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0747f96663ffc52910e62f3a7b740427f245ee630123de13fcd556dbad8727ea"

  strings:
    $s1 = "|software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}