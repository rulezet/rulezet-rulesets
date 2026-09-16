rule Virus_Hijack_Trojan_GenericKDZ_98113_336_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_336_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa4d2ce567d2206a520845974a179792d9297b22dc6ebb5c68a6aeb44dd8c2bd"

  strings:
    $s1 = "yCIE]+" fullword ascii
    $s2 = "snIp%B" fullword ascii
    $s3 = "E POGy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}