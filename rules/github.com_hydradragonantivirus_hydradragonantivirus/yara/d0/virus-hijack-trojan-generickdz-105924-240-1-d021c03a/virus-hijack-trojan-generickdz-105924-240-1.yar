rule Virus_Hijack_Trojan_GenericKDZ_105924_240_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_240_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7525859b551c5a4f842b05626fd61ab9c9f8c32ae94e058fe57823724ec8682e"

  strings:
    $s1 = "AutoIt v3 Script: 3, 3, 8, 1" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}