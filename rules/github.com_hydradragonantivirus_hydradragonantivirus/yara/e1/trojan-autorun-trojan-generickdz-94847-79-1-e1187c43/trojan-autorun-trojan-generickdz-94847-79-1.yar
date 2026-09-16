rule Trojan_Autorun_Trojan_GenericKDZ_94847_79_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_79_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bf46785f7640ad1240c3cce8969030029c56f88989759659b9a8f8b3b323b1d"

  strings:
    $s1 = "J)IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}