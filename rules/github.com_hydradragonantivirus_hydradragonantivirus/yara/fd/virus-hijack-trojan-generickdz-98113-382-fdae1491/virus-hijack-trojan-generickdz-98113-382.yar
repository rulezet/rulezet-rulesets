rule Virus_Hijack_Trojan_GenericKDZ_98113_382 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_382.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32327aa9a9a1b55c3339a1cbf5844d99ad785547b84565d35adc565b3b23584f"

  strings:
    $s1 = "E4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}