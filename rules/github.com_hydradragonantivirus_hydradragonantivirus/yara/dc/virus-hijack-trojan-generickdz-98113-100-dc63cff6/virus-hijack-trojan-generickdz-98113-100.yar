rule Virus_Hijack_Trojan_GenericKDZ_98113_100 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_100.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8aa19c2bf6fa97f6d7e538cb3aeb50469462810c6d006ac6da45c61015f27268"

  strings:
    $s1 = "i4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}