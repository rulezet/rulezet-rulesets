rule Trojan_Autorun_Trojan_GenericKD_72517131_190_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_190_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c036b7ee0647f341af56c4f6d4fce1ac676af15e2865a13630524d8f8c5b71a"

  strings:
    $s1 = "W>DIER{j" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}