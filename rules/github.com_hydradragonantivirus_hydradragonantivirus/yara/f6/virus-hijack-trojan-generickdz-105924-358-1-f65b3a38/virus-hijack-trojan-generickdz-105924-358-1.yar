rule Virus_Hijack_Trojan_GenericKDZ_105924_358_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_358_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7bcea02eb7c9fc65b811d1774963471a05e7a35c1060bad190b35db49aa2281"

  strings:
    $s1 = "]}}dIgs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}