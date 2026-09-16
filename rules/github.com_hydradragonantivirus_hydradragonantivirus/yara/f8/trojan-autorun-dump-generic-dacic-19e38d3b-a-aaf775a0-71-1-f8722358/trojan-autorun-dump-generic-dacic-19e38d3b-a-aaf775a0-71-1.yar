rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_71_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_71_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "806541ecab3cb957ccca7f6479f2f14ac7cba5fd0ffb4e118cc17a164c31b440"

  strings:
    $s1 = "XOracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}