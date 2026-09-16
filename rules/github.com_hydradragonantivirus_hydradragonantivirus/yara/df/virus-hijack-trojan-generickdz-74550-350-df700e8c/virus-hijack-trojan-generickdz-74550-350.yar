rule Virus_Hijack_Trojan_GenericKDZ_74550_350 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_350.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fee00d01f411d0de1f6ab9831bbe198c4f836a6dd57322a61f2e905c2696801"

  strings:
    $s1 = "VtFZg\"o[teFF" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}