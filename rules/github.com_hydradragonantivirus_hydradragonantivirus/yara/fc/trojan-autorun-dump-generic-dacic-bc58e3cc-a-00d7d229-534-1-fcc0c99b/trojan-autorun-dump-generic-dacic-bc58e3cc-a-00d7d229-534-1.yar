rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_534_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_534_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "298451a075c1c1e10e4e45afd7a009e6dfc7bdcbcd02a106ec73e764304c8959"

  strings:
    $s1 = "*software manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}