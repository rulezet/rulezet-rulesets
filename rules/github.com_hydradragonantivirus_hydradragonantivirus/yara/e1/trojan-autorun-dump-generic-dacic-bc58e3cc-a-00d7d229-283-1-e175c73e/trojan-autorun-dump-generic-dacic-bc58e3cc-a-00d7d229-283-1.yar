rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_283_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_283_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "114671a769b1fdec4c3425ff20e3764cdd3e5494020b86d8b254deb3a1f38690"

  strings:
    $s1 = "}~iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}