rule Virus_Sysbot_Trojan_GenericKD_61340032 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.61340032.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af57b91d7dc10c3af665f6c3f1942734e338b3c11f5bd577fd2d6b33de647da9"

  strings:
    $s1 = "!Th D program cannot be run in DOS mode." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}