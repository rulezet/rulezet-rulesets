rule Virus_Hijack_Trojan_GenericKDZ_105924_450_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_450_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b509056819c41b1c4bf035a29ec1a6cf92ed558163e319a0da84cf8774442486"

  strings:
    $s1 = "ROar(L#e" fullword ascii
    $s2 = "shAD]S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}