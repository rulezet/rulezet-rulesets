rule Virus_Hijack_Gen_Trojan_ShellObject_v4Z_aqH1LVc_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v4Z@aqH1LVc_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe2dbf96225f9bb3d85af2e56a774d425a7ed1777edfd728f47701470a4aabf8"

  strings:
    $s1 = "Copyright 2020 Google LLC. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}