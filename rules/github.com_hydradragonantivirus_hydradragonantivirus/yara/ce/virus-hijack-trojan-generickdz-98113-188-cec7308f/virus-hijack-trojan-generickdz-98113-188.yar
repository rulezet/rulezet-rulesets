rule Virus_Hijack_Trojan_GenericKDZ_98113_188 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_188.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29c3a8a6fd5bfe8fe36d3fb4c872cf1910440c7c62b33f2f51337b94c6755d82"

  strings:
    $s1 = "C04. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}