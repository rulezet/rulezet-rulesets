rule Virus_Hijack_Trojan_GenericKDZ_98388_116_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_116_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfcad2aaa4b9746ba5d5b83bdf5e871aa0a9cb5bcda8fca1acc3449b3fdc01fb"

  strings:
    $s1 = "flUtE?$" fullword ascii
    $s2 = "9Q@LOkAo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}