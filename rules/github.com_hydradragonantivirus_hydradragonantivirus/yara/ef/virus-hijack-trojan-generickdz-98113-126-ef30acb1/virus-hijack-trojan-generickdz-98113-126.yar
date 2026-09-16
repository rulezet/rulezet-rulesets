rule Virus_Hijack_Trojan_GenericKDZ_98113_126 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_126.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a89801ca299179e6ba60376c5c3d6af0747a309490587444392d47058ae4055"

  strings:
    $s1 = "DJ4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}