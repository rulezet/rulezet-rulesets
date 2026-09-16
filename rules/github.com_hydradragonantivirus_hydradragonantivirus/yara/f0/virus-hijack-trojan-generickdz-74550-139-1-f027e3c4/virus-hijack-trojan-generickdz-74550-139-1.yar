rule Virus_Hijack_Trojan_GenericKDZ_74550_139_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_139_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd2f7d6db93ea3259af86c09c7c793896877406eacb1fc9904933881b36308d9"

  strings:
    $s1 = ".64!fEUd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}