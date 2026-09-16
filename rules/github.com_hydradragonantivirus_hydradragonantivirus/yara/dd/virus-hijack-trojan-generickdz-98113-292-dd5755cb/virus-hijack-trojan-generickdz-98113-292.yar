rule Virus_Hijack_Trojan_GenericKDZ_98113_292 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_292.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba59edba6c74aa279b8b1d0161ccf82d253a8a0c125d963f2aa85ba083d8106b"

  strings:
    $s1 = "ss4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}