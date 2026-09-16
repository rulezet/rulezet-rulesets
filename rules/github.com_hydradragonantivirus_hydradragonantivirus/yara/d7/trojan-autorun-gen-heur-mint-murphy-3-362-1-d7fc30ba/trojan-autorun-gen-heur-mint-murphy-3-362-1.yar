rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_362_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_362_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16966d6610665f6c87f0b6ae065b80226fef2f7e0502807f22313de723206d10"

  strings:
    $s1 = "_your order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}