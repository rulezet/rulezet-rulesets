rule Virus_Hijack_Trojan_GenericKDZ_98388_39_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_39_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa67eba605e2d76becc2afb68949bf1713acfd169d3fdc60b8a0e49e914e8cc4"

  strings:
    $s1 = "]&nuKe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}