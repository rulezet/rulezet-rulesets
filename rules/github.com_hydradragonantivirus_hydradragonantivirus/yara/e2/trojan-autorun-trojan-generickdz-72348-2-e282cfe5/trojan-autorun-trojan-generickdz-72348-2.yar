rule Trojan_Autorun_Trojan_GenericKDZ_72348_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.72348_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e62465166d07dc23f79559835c136fae67f5d6933d3cf816ce0bb96965841b7"

  strings:
    $s1 = "bEsA`>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}