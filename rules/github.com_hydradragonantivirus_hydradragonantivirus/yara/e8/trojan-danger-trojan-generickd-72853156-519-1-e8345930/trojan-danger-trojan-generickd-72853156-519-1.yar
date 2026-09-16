rule Trojan_Danger_Trojan_GenericKD_72853156_519_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_519_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "546894bafe3cffba2c5ed7d1885ed691fd923abf70e7f58f7ff489484e50deea"

  strings:
    $s1 = "IntegratX with SOAP" fullword ascii
    $s2 = "Read{&" fullword ascii
    $s3 = "o}Default" fullword ascii
    $s4 = "(About " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}