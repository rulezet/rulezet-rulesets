rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_217_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_217_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2818b5eb4fa374185ba7da24e1be97cf9ea9ad660632ae86526c1e1ab108b890"

  strings:
    $s1 = "If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}