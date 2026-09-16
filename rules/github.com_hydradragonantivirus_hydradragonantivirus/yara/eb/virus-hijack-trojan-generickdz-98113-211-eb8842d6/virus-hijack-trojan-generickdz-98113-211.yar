rule Virus_Hijack_Trojan_GenericKDZ_98113_211 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_211.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18775e29f5aefe1264432176bcdee9285434f50b49f970854059309f56624e38"

  strings:
    $s1 = "_4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}