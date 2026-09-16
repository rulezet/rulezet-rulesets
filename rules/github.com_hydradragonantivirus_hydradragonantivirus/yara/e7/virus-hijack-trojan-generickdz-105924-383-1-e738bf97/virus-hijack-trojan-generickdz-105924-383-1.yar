rule Virus_Hijack_Trojan_GenericKDZ_105924_383_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_383_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47a367cedd155ad02132125b760fd8cf14a0c1cd7db8ea6dabbb57d95d827ada"

  strings:
    $s1 = "_*RUMp" fullword ascii
    $s2 = "frAb`$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}