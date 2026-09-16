rule Virus_Hijack_Trojan_GenericKDZ_105924_468_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_468_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fc3787f8b3288e5ea958f8ae460f2e8c630cedb8a273b5de98543a28e7bb0f7"

  strings:
    $s1 = "\\b(Knyaz*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}