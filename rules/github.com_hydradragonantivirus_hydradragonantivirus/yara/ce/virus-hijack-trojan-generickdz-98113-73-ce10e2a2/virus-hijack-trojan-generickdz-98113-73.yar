rule Virus_Hijack_Trojan_GenericKDZ_98113_73 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_73.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a218e4bb217aa53571cd1f6404d7a6b81c64d750ec3fc7ae540fd48248cb838e"

  strings:
    $s1 = "&*4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}