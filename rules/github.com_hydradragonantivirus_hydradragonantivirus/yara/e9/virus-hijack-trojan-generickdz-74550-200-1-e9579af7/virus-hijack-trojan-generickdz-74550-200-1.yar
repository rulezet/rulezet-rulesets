rule Virus_Hijack_Trojan_GenericKDZ_74550_200_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_200_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a37828a6d60ea36a7e5edb2922bfcb671acefab6e1ef745b44dde2fe7c60f69f"

  strings:
    $s1 = "TiNG dS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}