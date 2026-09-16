rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_71_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_71_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ac9e951fa7da3903b42eae4363d0c3aad9edf45569373d0f81e0c92adc81b70"

  strings:
    $s1 = "[your entire employee population." fullword ascii
    $s2 = "^0{tREf" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}