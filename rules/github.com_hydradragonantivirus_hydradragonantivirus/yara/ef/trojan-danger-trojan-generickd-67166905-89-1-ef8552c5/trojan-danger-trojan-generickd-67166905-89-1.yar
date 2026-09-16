rule Trojan_Danger_Trojan_GenericKD_67166905_89_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_89_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54551f25e02605eadac5202fc25462d744181c495de4cdc5c51b762854b72d6d"

  strings:
    $s1 = "5policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}