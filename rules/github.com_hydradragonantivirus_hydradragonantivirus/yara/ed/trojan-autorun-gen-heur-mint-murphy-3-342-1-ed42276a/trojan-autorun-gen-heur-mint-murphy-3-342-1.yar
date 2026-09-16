rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_342_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_342_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c660f7784c7690a97a63435fedabd99ea99196a85a640237819a369adc1c4c7"

  strings:
    $s1 = "/q4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}