rule Virus_Hijack_Trojan_GenericKDZ_74550_99_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_99_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd80053f33e94658353b80d8307cc8c5f4be81754c6ed3adfb190eae25d88736"

  strings:
    $s1 = ";Toff." fullword ascii
    $s2 = "6;piLi" fullword ascii
    $s3 = "sTay*u" fullword ascii
    $s4 = "V?GAlP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}