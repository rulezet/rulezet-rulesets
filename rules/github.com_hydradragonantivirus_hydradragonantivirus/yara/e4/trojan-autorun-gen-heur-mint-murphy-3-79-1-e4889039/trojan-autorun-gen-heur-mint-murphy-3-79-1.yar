rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_79_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_79_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da0093fc2740568b18ffd38d396292ecf83ef6aace466d1e74cafc7cea64c866"

  strings:
    $s1 = "!hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}