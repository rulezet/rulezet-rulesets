rule Virus_Hijack_Trojan_GenericKDZ_105924_568_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_568_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba91f7973caf3dc7f3ccb40f22e54f5c26e4a947b6e79f2a902f300149981897"

  strings:
    $s1 = ")HArd;\"R" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}