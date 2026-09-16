rule Trojan_Autorun_Gen_Heur_Mint_SP_Urelas_1_4 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.SP.Urelas.1_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3983c5a8fb63e2367d504d8124cd9686e3e61329931be30aaa4532ed786d81d"

  strings:
    $s1 = "04. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}