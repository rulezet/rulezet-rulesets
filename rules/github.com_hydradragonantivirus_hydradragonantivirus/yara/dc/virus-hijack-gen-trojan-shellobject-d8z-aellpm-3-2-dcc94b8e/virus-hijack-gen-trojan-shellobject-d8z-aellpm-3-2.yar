rule Virus_Hijack_Gen_Trojan_ShellObject_D8Z_aeLlPm_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.D8Z@aeLlPm_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd0b260da045c068d6455166a3275dcc65ba40435ee42480db2b2ef10b6f3612"

  strings:
    $s1 = "hEWt`ZI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}