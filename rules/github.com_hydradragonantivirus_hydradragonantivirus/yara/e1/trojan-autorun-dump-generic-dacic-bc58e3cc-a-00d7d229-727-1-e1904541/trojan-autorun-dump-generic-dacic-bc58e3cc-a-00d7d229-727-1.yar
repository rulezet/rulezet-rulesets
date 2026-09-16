rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_727_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_727_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4526906730e2db2f4867afde1dff22f42effabe58d9ca022c0434426ebb9e5c4"

  strings:
    $s1 = "zyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}