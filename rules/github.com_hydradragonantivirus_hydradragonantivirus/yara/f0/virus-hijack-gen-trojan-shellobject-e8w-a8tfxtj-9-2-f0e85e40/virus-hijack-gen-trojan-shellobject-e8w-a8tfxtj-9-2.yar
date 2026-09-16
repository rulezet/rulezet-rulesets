rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_a8TFxTj_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@a8TFxTj_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a72b536f5778f1c5244b31b09576354b927b2956f218ce25689eda77d5e3d64"

  strings:
    $s1 = "Copyright (c) SkinBox Technology All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}