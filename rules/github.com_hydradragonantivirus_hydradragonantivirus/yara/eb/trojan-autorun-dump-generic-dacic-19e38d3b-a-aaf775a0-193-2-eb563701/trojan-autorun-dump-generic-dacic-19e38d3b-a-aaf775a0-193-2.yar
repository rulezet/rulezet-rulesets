rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_193_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_193_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c28bdcca27a086b45e7e1757ee57a007076ea9ba9cff463b44e9e7080db93e"

  strings:
    $s1 = "CallDll Version 1.0" fullword wide
    $s2 = "<Unknown:%d>" fullword wide
    $s3 = "Filtrate" fullword ascii
    $s4 = "Fabout:blank" fullword ascii
    $s5 = "Typically" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}