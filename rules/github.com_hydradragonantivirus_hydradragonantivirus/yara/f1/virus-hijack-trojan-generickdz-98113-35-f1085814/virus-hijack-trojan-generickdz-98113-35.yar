rule Virus_Hijack_Trojan_GenericKDZ_98113_35 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_35.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dfa1a6f99d387032634e487bd148aa0e713b149066bfa18579f57bae19b47f0"

  strings:
    $s1 = "84. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}