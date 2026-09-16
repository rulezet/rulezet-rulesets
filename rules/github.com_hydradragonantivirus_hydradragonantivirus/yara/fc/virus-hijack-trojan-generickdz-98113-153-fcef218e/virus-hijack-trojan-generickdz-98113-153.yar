rule Virus_Hijack_Trojan_GenericKDZ_98113_153 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_153.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13eeaa8dda60a20819a82c2ac77bfdb46b47b805e7edfb21d71890c02105ac09"

  strings:
    $s1 = "l4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}