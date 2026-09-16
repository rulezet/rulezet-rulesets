rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_74_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_74_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7650446b8e594005247fecbf39df012ad1cab7609d635cd1716c84d8566fd56c"

  strings:
    $s1 = "]by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}