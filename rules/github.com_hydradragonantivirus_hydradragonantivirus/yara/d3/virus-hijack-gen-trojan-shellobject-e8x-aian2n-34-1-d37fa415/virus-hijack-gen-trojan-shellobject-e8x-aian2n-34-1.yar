rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_34_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_34_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4888a5cb596bd8696b9041873e43c22444558101bd5cc18adc20edb9751d576b"

  strings:
    $s1 = "moldable" fullword ascii
    $s2 = "broguery" fullword ascii
    $s3 = "Groggery" fullword ascii
    $s4 = "Acquirable" fullword ascii
    $s5 = "Adorably" fullword ascii
    $s6 = "Devoto qs medico" fullword wide
    $s7 = "Tronco jp false mance" fullword wide
    $s8 = "Cretin" fullword ascii
    $s9 = "Ejecta" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}