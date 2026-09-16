rule Virus_Hijack_Trojan_GenericKDZ_105924_349_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_349_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8abd8a7a2d8e068905cda9b1729ccaca21f4dc7b2de0673649e77fb9e4c87b86"

  strings:
    $s1 = "L!;LaWK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}