rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_126_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_126_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79730578533bf533b404e1142cf8fbf09ef97d625acf85c779bc3d83e65dd025"

  strings:
    $s1 = "sLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}