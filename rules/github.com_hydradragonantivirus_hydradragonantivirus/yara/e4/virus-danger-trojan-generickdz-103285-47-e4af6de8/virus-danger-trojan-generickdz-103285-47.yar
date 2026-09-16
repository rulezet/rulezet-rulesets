rule Virus_Danger_Trojan_GenericKDZ_103285_47 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_47.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a7e5c15ed0507efc0fa6c7af0ab3743c49c8b164fedaebaf680cf799a1aa598"

  strings:
    $s1 = "rZpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}