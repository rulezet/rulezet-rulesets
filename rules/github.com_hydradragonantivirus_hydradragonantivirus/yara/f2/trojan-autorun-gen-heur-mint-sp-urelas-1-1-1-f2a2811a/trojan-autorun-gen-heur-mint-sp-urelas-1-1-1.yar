rule Trojan_Autorun_Gen_Heur_Mint_SP_Urelas_1_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.SP.Urelas.1_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75e700ddc55be8133dd04ad9e60170d516482177f5f08bee78af67dbb6a627ec"

  strings:
    $s1 = "P4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}