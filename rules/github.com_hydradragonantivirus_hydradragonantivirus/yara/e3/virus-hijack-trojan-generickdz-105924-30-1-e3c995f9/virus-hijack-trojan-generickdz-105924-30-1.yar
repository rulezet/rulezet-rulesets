rule Virus_Hijack_Trojan_GenericKDZ_105924_30_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05fe0e290183e949b0dd33df32e56b801216ea7d4b5151b056ecee4783a1ca6f"

  strings:
    $s1 = "#URus)" fullword ascii
    $s2 = "Rife%s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}