rule Virus_Hijack_Trojan_GenericKDZ_74550_282_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_282_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70ee189e99039ca40019dad04968a2bf3d75f6b3a602d87cbf01123f22e0e1d5"

  strings:
    $s1 = "taWN&\\a|k" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}