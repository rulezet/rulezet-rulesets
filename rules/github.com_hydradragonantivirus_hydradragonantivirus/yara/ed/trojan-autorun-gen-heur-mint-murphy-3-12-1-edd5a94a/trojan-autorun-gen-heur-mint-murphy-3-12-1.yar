rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_12_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5402d1da7abf2c2691e54998d284aa48a71da2d6cd7681747441240e60f1dce4"

  strings:
    $s1 = "CLue?H" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}