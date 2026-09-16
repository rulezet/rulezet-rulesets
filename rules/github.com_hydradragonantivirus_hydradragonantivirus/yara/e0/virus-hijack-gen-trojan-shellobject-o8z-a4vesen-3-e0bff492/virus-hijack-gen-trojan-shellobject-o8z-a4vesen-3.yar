rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_a4vesEn_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@a4vesEn_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7af115567c4521bdbe21726fecf5c6ce179d38598477f83852719b08c3ae896"

  strings:
    $s1 = "Amicrosoft.com/office/backup. You may not distribute the backup copy of the software. You may use it" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}