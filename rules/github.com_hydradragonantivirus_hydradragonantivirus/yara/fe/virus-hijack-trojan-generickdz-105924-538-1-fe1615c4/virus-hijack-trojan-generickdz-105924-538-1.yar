rule Virus_Hijack_Trojan_GenericKDZ_105924_538_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_538_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ca609bd17d187b683ba5b392a4baa36ebf3b7b881af1e8fd9f799ab9168749b"

  strings:
    $s1 = "-*jURy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}