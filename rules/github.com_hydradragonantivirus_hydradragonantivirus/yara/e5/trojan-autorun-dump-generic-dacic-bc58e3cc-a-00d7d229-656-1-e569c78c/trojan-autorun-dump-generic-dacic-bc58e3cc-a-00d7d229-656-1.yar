rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_656_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_656_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df81bbd8e63844ec7bdf0adef3106a3d0541f15b13fe026c43db7059c75f03e7"

  strings:
    $s1 = "RURu)U" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}