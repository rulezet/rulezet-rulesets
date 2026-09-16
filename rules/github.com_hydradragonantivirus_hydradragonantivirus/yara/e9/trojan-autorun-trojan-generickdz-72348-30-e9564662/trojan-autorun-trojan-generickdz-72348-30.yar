rule Trojan_Autorun_Trojan_GenericKDZ_72348_30 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.72348_30.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e56711e629c52b5351e01e9ddf7669c9c510bdff46917e042c9a737812d35801"

  strings:
    $s1 = "services. We may also share it with others, such as hardware and software" fullword ascii
    $s2 = "s fees. You and Microsoft agree to the terms governing procedures, f" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}