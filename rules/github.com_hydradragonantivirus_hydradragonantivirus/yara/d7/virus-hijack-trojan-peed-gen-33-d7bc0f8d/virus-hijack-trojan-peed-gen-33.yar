rule Virus_Hijack_Trojan_Peed_Gen_33 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_33.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecd62e6f3e3f0af19b0b7b10052721cec7cc47a91392aa28ff75ab64d100a18b"

  strings:
    $s1 = "CRAb@[;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}