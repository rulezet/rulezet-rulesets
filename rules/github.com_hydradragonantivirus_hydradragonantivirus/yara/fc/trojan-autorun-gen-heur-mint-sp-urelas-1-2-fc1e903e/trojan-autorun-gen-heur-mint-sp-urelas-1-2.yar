rule Trojan_Autorun_Gen_Heur_Mint_SP_Urelas_1_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.SP.Urelas.1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e98877445a87c4833afc01039882c7a4d128c496d5c0caafdb0ee23bc165d2a"

  strings:
    $s1 = "GolfUpdate, Version 1.0" fullword wide
    $s2 = "About GolfUpdate" fullword wide
    $s3 = "pl]Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}