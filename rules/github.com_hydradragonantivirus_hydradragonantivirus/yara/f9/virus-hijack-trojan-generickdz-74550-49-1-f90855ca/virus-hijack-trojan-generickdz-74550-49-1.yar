rule Virus_Hijack_Trojan_GenericKDZ_74550_49_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_49_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "848c3f5c72d2ec53a6b3e8c4b0b3fcd5c8c2fe68f9e9eabdc03b5f14099106a2"

  strings:
    $s1 = "Z[cUBI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}