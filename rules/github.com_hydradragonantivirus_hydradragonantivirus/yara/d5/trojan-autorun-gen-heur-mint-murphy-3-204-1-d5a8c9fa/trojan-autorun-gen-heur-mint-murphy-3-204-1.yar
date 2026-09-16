rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_204_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_204_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59b304a1e5c50de9b718d3ce00c5374cd41822e8ac63a755dc5d7310c24f4f63"

  strings:
    $s1 = "heme*em" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}