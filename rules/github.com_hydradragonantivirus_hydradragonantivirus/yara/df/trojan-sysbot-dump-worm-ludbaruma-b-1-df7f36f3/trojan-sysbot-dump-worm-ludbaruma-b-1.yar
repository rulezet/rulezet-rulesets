rule Trojan_Sysbot_Dump_Worm_Ludbaruma_B_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Dump.Worm.Ludbaruma.B_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ada365b4f5893dbf6d255da1b42a24cc1896fe65d5344822e61208f49b2fe7a"

  strings:
    $s1 = " in DOS mode." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}