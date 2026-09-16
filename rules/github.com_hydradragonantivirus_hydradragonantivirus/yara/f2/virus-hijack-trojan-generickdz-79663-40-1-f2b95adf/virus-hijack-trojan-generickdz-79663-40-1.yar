rule Virus_Hijack_Trojan_GenericKDZ_79663_40_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_40_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e044b229ad090a7e0095df991f6cff3651cb13b4daa3fd2df6bc7d9c8262fee4"

  strings:
    $s1 = "W}WYnD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}