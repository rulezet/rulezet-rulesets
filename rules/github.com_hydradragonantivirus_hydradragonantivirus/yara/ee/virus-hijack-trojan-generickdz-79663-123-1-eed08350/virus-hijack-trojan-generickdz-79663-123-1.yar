rule Virus_Hijack_Trojan_GenericKDZ_79663_123_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_123_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62bf0902946da98f659de9b9986289a47cc00db05aefc2466a654027c3056282"

  strings:
    $s1 = "MERl`u" fullword ascii
    $s2 = "De`TERn." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}