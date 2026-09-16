rule Virus_Hijack_Trojan_GenericKDZ_98113_32 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_32.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a05a530e00c747c318501e534606fc4ee139c9141436c5c41d00720e5ed5a5a9"

  strings:
    $s1 = "~14. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}