rule Virus_Hijack_Trojan_GenericKDZ_105924_311_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_311_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51b65a8f266104962850a90857a19754152c7734f0fbc49841e16f080e74a178"

  strings:
    $s1 = "TOHo{,h" fullword ascii
    $s2 = "b;!hOga" fullword ascii
    $s3 = "BeRM{9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}