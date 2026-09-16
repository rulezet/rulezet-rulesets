rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_111_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_111_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "886a789b66d39654a0064600ede9a5e717e75867349fb483d7c1a6cf91a2acc2"

  strings:
    $s1 = "ziLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}