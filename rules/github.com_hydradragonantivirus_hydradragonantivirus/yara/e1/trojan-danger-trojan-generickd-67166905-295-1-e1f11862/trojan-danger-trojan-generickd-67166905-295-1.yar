rule Trojan_Danger_Trojan_GenericKD_67166905_295_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_295_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fd7fa9651593bd6a0bd1d6f3a6807ad3d3b07e75d91283b29424f5ad5a93815"

  strings:
    $s1 = "\"MWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}