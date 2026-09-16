rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_529_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_529_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f69e69e84083965858ba9b39e5180ad5bbf06e9c02adb9bbf53b699876918cf"

  strings:
    $s1 = "nTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}