rule Virus_Hijack_Trojan_GenericKDZ_105924_243_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_243_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7df3639e2bc64d7b6d2fd9eb7d36ee3de0e0d47a8953eef9970fcfcc2ba4215"

  strings:
    $s1 = "AutoIt v3 Script: 3, 3, 8, 1" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}