rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_36_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_36_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ef2dd5288a40948b6694adc17f5f7fffa283b08400f04dc965f6077d189dbb2"

  strings:
    $s1 = "LIte&T4" fullword ascii
    $s2 = "PUky[HJ" fullword ascii
    $s3 = "#qsD:Homo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}