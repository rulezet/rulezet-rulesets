rule Virus_Hijack_Trojan_GenericKDZ_105924_448_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_448_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f08e815a542b9d7b592c0cd4f6a13b742fa598dfa8cd72d2aafdc3de238423a3"

  strings:
    $s1 = "#e<hOsT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}