rule Trojan_Autorun_Trojan_GenericKDZ_94847_52_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_52_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bb1b21419fc2676368867e07e7740f69a4a68cf3b2ba6df164cc0b4ea3497bb"

  strings:
    $s1 = "jorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}