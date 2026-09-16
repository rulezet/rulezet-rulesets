rule Trojan_Autorun_Trojan_GenericKDZ_72348_20 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.72348_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a96ed6c8941b94d9b36a7ae785a1a3b9ffb043b91908c9d69764b226ad79e4ac"

  strings:
    $s1 = " edition software may not be used for commercial, non-profit, o" fullword ascii
    $s2 = "xes and expenses. You agree that you have not relied on" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}