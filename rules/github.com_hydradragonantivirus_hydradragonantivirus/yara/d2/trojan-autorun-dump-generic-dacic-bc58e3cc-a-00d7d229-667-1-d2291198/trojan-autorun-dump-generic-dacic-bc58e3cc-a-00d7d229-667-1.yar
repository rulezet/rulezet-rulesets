rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_667_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_667_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3950910d556bb24788f4e75521144558fa8cce219f79a85b6184f29f5bb7bef"

  strings:
    $s1 = "Hsoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}