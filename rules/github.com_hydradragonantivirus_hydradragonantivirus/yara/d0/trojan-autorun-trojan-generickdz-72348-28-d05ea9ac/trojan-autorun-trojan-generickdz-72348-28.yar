rule Trojan_Autorun_Trojan_GenericKDZ_72348_28 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.72348_28.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dff41854b68387b45df24b487e9b48a58938ef1bc0711ea7d69262c887653f69"

  strings:
    $s1 = " edition software may not be used for commercial, non-profit, o" fullword ascii
    $s2 = "xes and expenses. You agree that you have not relied on" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}