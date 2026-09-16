rule Virus_Hijack_Trojan_GenericKDZ_74550_323_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_323_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a4781fc98a589886608581a23dfa088ab452862ac9d878c96a94911b677422d"

  strings:
    $s1 = "TAuPO:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}