rule Trojan_Danger_Trojan_GenericKD_72853156_190_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_190_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2945cf67ac30fd1db15946aef8494ca6d2183323a788f5637154c0f99042b5de"

  strings:
    $s1 = "Copyright 2014 SongHaret" fullword wide
    $s2 = "Copyright (C) 2014 Hudfteff" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}