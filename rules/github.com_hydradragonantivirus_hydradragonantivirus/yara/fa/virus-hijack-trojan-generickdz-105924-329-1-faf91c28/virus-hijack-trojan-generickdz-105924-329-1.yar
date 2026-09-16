rule Virus_Hijack_Trojan_GenericKDZ_105924_329_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_329_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5b1a69347ea1aabb59c295ab25a187d67a2a2a466d1a27def76a012006a2649"

  strings:
    $s1 = "lOCk{p" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}