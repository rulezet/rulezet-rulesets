rule Virus_Hijack_Trojan_GenericKDZ_105924_241_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_241_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e5fa283b88a994183b4a705d77bebc77313158b5735001141e82cee2ad8e444"

  strings:
    $s1 = "AutoIt v3 Script: 3, 3, 8, 1" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}