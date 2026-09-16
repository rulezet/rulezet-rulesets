rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_537_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_537_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09da6d74e68a79ccfd4a6ba87d644fad7f71dde0d60c9459557dc93228e80ecd"

  strings:
    $s1 = "NMto be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of this" fullword ascii
    $s2 = ") as well as such courses `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}