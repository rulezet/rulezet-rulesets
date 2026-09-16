rule Virus_Hijack_Trojan_GenericKDZ_105924_520_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_520_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2847d67068b0d1f6354d0cde583c59b6d94431ea1cefff67cdba4a9a57f6a411"

  strings:
    $s1 = "EdGE?a" fullword ascii
    $s2 = "MEsA;<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}