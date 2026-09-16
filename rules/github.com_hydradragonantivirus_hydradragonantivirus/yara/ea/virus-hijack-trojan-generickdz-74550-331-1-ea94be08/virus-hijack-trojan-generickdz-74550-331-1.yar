rule Virus_Hijack_Trojan_GenericKDZ_74550_331_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_331_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed888b0d6de234e17e292815183bc09a0f2d3d77d72077105f2b18d3ffe4c46f"

  strings:
    $s1 = "FLot(hU7" fullword ascii
    $s2 = "Naio[E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}