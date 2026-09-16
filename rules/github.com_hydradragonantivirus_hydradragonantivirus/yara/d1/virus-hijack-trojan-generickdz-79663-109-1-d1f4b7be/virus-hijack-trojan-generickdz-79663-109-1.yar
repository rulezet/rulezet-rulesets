rule Virus_Hijack_Trojan_GenericKDZ_79663_109_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_109_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba38c64eb5cec7a98e861c449b679d5af90277ac6698248c8d103804c7812228"

  strings:
    $s1 = "`WeLt@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}