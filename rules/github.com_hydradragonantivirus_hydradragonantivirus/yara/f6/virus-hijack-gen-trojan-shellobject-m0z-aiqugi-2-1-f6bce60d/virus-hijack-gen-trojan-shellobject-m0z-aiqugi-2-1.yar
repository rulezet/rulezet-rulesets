rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "037c0968f1fa09401ef322fc52cb7752985472334f466ab1d7bcbcd4c7579a6c"

  strings:
    $s1 = "#@VIse" fullword ascii
    $s2 = "``deRn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}