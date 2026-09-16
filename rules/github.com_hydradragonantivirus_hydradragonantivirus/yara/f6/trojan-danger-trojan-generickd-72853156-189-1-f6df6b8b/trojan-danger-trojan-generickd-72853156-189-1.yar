rule Trojan_Danger_Trojan_GenericKD_72853156_189_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_189_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b250747d5d72b071360f7bbb568d91237b4508ef21a1ff096a6885c79abe1bc5"

  strings:
    $s1 = "Copyright 2014 AiosfdHuisfe" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}