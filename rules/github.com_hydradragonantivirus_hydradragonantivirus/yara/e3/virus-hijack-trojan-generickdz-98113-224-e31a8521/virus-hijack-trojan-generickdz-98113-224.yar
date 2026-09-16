rule Virus_Hijack_Trojan_GenericKDZ_98113_224 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_224.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34619edb2539385746a247f7fe2831a2de6f7ed9fea5e3140e2263d631f8e91a"

  strings:
    $s1 = "#u4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}