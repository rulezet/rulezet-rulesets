rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_114_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_114_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec4d48d5b96e0d0449caeafb62744e84c4721ec04498ad2c8818bea96dacbf25"

  strings:
    $s1 = "Zand services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}