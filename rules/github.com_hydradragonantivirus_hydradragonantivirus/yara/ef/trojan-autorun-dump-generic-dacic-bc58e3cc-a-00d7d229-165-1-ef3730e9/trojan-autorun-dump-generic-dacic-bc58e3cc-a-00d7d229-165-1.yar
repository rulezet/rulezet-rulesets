rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_165_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_165_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5903c65c111331a87efd03313fbbc2ba22b7d6481a409a8f7e64347d3959145"

  strings:
    $s1 = "NgiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}