rule Trojan_Danger_Trojan_GenericKD_67166905_348_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_348_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "122a0c85ad89b08ce57f88a2df1137448e8af4e317ea852b7e621f9cf53396ae"

  strings:
    $s1 = "xpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii
    $s2 = "{@dEAD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}