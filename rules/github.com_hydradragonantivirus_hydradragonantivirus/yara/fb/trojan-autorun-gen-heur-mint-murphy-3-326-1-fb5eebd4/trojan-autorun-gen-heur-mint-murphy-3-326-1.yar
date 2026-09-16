rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_326_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_326_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eba77ff313b219981b8709538cd56a584e4b8c7f3ca5a9679544bcc4938d698d"

  strings:
    $s1 = "K4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}