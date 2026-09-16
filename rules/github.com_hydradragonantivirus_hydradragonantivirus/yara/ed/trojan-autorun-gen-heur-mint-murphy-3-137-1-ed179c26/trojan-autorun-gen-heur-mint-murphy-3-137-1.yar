rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_137_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_137_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c00692af1414b323a74d00cc8fa5f7396ea43f5752d06cace5a2cefe86c1b70"

  strings:
    $s1 = "U{khan" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}