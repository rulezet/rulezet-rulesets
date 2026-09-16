rule Virus_Hijack_Trojan_GenericKDZ_98113_47_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_47_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf074ccbdf1d1a3118a2e837be502179de468ab9c9ec08b3366774beb6c16662"

  strings:
    $s1 = "Wkezes}ShaH" fullword ascii
    $s2 = "rINe 3" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}