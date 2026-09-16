rule Virus_Hijack_Trojan_GenericKDZ_94849_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc695bb638efa237ee926a5ee7a98704442dda96da7f74811bfd9f34eec2f64"

  strings:
    $s1 = "WOmB%1%a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}