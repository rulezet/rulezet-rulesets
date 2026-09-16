rule Trojan_Danger_Trojan_GenericKD_72853156_184_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_184_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88e9856a6267651868d7419462d5f6e4c839de0b58c100af24de0d8336f7a2d8"

  strings:
    $s1 = "Copyright (C) biydtfrer" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}