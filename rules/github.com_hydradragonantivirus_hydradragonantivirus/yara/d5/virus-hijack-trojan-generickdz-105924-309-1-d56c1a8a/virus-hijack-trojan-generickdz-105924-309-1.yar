rule Virus_Hijack_Trojan_GenericKDZ_105924_309_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_309_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a383e73a38d0e10cfde96737bcbc6e785d41d1a1e47690699b998d1b3b722b42"

  strings:
    $s1 = "lAkY)Gu#P" fullword ascii
    $s2 = "JEST]C" fullword ascii
    $s3 = "M?dais" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}