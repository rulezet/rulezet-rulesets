rule Virus_Hijack_Trojan_GenericKDZ_105924_556_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_556_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0594a82ae8240371b0b0eab0133eadbd7620969166c7d63a929e9efea70ee289"

  strings:
    $s1 = "hACK[W" fullword ascii
    $s2 = "&@siDE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}