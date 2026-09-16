rule Virus_Hijack_Trojan_GenericKDZ_105924_549_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_549_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c051a795afd43746b948c3411da504e9cbfa041ad73e382ac4047771892da85f"

  strings:
    $s1 = "Tryp&u" fullword ascii
    $s2 = "LAICQ\\" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}