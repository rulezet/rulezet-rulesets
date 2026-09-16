rule Virus_Hijack_Trojan_GenericKDZ_103285_776 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_776.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a45445b97f8b6f4c6bdae385ad041b4cfe515667e8a00e6b15fdf1fbdeb28b0"

  strings:
    $s1 = ">stAP*H" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}