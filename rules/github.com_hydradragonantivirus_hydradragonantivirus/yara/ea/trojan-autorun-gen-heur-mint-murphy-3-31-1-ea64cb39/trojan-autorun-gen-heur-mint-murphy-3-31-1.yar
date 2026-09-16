rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_31_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5762d320d6dedf9e551ad31c41412f8ef3999b3e13e3c5fa200f1136a29a7e0"

  strings:
    $s1 = "=o4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}