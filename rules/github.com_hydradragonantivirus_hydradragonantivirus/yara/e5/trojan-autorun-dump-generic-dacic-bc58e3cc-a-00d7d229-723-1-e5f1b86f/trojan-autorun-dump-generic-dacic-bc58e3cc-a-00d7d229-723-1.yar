rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_723_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_723_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de36c484c70f5a1b5736b72f426bc8858e243d31787037fdecba00dc25ef4689"

  strings:
    $s1 = "qof the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}