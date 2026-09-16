rule Trojan_Autorun_Gen_Trojan_Heur_D_cmIfbi3RsP_3_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f39b5b5fe9e058272c30b7565a263bfc0b99e7089261b753b668de84c2af830c"

  strings:
    $s1 = "Z(4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}