rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_390_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_390_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17524adb1bdc251d3ee1ece065b74f8c65e109736488b61f26822fd5c45279b9"

  strings:
    $s1 = "Fare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}