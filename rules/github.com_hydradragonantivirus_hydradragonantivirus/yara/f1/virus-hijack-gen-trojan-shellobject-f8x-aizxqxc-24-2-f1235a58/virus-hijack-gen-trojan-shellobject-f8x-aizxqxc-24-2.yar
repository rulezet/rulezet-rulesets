rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_24_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_24_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "325c6194c26718a54b3c0e011cbbdd222e10ba6511487667acfccbc20f3f354d"

  strings:
    $s1 = "Host process for Windows services" fullword wide
    $s2 = "!Host process for Windows services" fullword ascii
    $s3 = "LizGuard Enterprise" fullword ascii
    $s4 = "BigA!S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}