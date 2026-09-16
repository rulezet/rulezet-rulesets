rule Trojan_Hooker_Win32_Floxif_A_60 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_60.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28ec3c81a4ce786c2607cf0a354967c0c415809da9056022f37d421e89f8f3ae"

  strings:
    $s1 = "Copyright 2006-2014 iTianKong.com, all rights reserved." fullword wide
    $s2 = "tEAl:a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}