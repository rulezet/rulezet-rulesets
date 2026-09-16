rule Virus_Hijack_Trojan_GenericKDZ_98113_191 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_191.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de33813f113a85c0a5a8e322a182ec74ba0c545ed0da47e4867a162cf150efdb"

  strings:
    $s1 = "J4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}