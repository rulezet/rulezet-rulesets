rule Virus_Hijack_Trojan_GenericKDZ_74550_281_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_281_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c30aa030e1d6018920978f153a559663fd80c005b71bf4eb34f58d629828ce8"

  strings:
    $s1 = "pYal<:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}