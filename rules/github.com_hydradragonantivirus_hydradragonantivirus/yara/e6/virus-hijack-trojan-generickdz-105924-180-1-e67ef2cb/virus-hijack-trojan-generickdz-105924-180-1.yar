rule Virus_Hijack_Trojan_GenericKDZ_105924_180_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_180_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc65bcbb6a297dbed9be1067d2f67f921d21b9d2202f134f7a7c397148e93d33"

  strings:
    $s1 = "KERN`L32.dql" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}