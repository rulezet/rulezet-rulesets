rule Virus_Hijack_Gen_Trojan_ShellObject_uvZ_a8bSq4i_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uvZ@a8bSq4i_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5057e1ce3c24241507beeee464c41ef1c0de838f0ccc1958f2e4b7b80e9a3f69"

  strings:
    $s1 = "Copyright 2022 Google LLC. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}