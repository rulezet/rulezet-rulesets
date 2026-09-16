rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_3_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36760f04d92417db3f561300b7299161d9fccbd1910c9e5d9f42ba6983ff5917"

  strings:
    $s1 = "functionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}