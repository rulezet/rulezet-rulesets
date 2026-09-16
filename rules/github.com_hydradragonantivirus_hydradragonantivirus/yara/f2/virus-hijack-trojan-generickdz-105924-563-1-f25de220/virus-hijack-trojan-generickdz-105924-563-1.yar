rule Virus_Hijack_Trojan_GenericKDZ_105924_563_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_563_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d368c6baba08ebc456ae2a1b34500641a731329eef1e886e5365ac608e765398"

  strings:
    $s1 = "onza?T" fullword ascii
    $s2 = "tYke`Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}