rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_733_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_733_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "992a86bc129524bad325d4de5dd8d94e607f033fa9f4276524f8640cd8a70957"

  strings:
    $s1 = "MQOracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}