rule Virus_Hijack_Trojan_GenericKDZ_79663_125 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_125.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6d1e8961eb1c9f9ef746dbabfd531dc747c23f5f5f1e88dc9d23f2e9198782e"

  strings:
    $s1 = "BAtt;*" fullword ascii
    $s2 = "Cleam#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}