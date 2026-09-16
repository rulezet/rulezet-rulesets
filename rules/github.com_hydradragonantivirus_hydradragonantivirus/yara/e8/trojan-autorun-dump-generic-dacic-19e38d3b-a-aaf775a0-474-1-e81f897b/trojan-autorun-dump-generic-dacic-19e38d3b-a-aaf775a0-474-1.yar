rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_474_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_474_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a97763b86d668a3a398f1fea1d3c41c843a1c126ea3dad8dbe06cf550b4d55f"

  strings:
    $s1 = "#hOUR LICE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}