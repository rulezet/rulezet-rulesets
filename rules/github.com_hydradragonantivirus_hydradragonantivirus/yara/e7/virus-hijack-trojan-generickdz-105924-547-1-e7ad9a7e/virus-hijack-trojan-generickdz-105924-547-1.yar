rule Virus_Hijack_Trojan_GenericKDZ_105924_547_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_547_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62fd2937f4d73bd992a9b1e21bee33ba5be8009d0c539b8d670e9352d3816c68"

  strings:
    $s1 = "PaTa{\\" fullword ascii
    $s2 = "CEpa]8c" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}