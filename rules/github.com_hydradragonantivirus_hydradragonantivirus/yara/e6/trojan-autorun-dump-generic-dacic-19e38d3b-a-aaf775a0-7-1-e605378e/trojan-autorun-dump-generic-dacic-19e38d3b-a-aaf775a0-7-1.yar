rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_7_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5a45b5e86935b0407b202641b0dd5aef74e96bf427bc5db70baf5940d7e700a"

  strings:
    $s1 = "=[active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}