rule Virus_Hijack_Trojan_GenericKDZ_74550_172_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_172_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "466e6d491c8eaa1930a6c527fdc9173a8b51ed1a796bb2f88ef51017c6b0ac9b"

  strings:
    $s1 = ">LOUt]l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}