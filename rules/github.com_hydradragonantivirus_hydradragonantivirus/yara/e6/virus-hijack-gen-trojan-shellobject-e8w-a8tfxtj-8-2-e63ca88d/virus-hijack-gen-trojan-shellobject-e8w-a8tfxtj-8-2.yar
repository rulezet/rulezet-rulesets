rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_a8TFxTj_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@a8TFxTj_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3016a5c2c0d1ecc7053cc82f6b212bcd3a7bd155a1a92caebe2c597c12a3db2"

  strings:
    $s1 = "Copyright (c) SkinBox Technology All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}