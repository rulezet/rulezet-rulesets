rule Trojan_Danger_Trojan_GenericKD_72853156_86_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_86_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd8652a8265dcdeac3894c413b692a8ed98d33a22685d3c0923988467e38ed44"

  strings:
    $s1 = "Set objShell = Nothing" fullword wide
    $s2 = "Server: Apache/2.4.18 (Ubuntu)" fullword ascii
    $s3 = "CLIENT libcurl 7.54.1" fullword ascii
    $s4 = "KGS!@#$%server response timeout" fullword ascii
    $s5 = "Date: Fri, 14 Jul 2017 09:51:07 GMT" fullword ascii
    $s6 = "\"\"\", 0, true" fullword wide
    $s7 = "necko:classified" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}