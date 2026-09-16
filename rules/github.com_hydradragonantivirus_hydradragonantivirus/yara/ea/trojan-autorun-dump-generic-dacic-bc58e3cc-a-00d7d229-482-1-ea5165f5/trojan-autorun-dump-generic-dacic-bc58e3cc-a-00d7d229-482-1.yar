rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_482_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_482_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e3b7cf3ba0788b5ba52dd4a1edc45ad6c59056635ce74e5c90dfe43cd2c44b"

  strings:
    $s1 = "[are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}