rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_597_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_597_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac74104a1b708f73fb1b68098b94a9363399b14516e6fd6ddef429b43aed85c5"

  strings:
    $s1 = ") as well as such courses `" fullword ascii
    $s2 = "P@to be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of this" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}