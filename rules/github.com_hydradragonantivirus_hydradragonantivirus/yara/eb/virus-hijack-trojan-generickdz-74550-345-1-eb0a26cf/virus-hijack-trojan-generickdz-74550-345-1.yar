rule Virus_Hijack_Trojan_GenericKDZ_74550_345_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_345_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ab38db0f9bd80596e1588d021f289bae9b8d86b03f5579aa670b5d2927c78e6"

  strings:
    $s1 = "Hypo>?j" fullword ascii
    $s2 = "uplEg:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}