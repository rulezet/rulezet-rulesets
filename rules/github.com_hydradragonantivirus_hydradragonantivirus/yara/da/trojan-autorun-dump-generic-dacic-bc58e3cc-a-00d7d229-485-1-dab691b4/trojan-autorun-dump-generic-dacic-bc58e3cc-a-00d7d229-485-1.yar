rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_485_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_485_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f13914f21dbafb8fe731ad4a514f4496aef75c2bfb62cc2624ca87d0048656fb"

  strings:
    $s1 = "prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}