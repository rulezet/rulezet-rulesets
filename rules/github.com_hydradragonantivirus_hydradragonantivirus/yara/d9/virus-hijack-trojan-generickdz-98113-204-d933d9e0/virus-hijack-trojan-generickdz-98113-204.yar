rule Virus_Hijack_Trojan_GenericKDZ_98113_204 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_204.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90c3ed777fee106841c47ecb3089382bf3d59efdba8931a6651fbd9bf4b2ec03"

  strings:
    $s1 = "?~4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}