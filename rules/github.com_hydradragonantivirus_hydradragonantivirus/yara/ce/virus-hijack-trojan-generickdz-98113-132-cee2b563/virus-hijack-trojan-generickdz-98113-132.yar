rule Virus_Hijack_Trojan_GenericKDZ_98113_132 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_132.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d5bbb58e3aded83a2abadad655b7d69f05fd135d1f43c66499ca904be4c72dc"

  strings:
    $s1 = "d4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}