rule Virus_Hijack_Trojan_GenericKDZ_98113_243 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_243.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80b2eaf620d6368e990b8d36efd359c7ec3244d47bb78031c46589972a8a4d93"

  strings:
    $s1 = "Vor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}