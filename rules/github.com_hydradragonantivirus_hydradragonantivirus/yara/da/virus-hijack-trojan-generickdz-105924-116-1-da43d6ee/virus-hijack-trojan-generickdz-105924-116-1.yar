rule Virus_Hijack_Trojan_GenericKDZ_105924_116_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_116_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12a224ad7c76af51800fbbff5265e6df3e123cf0098b6b2214bfbd3621ad8aa1"

  strings:
    $s1 = "Eddy<o" fullword ascii
    $s2 = "T$wEEn" fullword ascii
    $s3 = "B:cOul" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}