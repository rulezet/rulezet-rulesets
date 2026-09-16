rule Virus_Hijack_Trojan_GenericKDZ_74550_155_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_155_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fc62f322baae343e9bdfb56cf05d748b59f0f43d2a22ef2722cc1ba27904d78"

  strings:
    $s1 = "pand'g" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}