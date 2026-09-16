rule Virus_Hijack_Trojan_GenericKDZ_98113_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21822781e9f2be0965ba6212ca000cf2df1f7f5d87e04582fe2f69eb066edcc8"

  strings:
    $s1 = "prIg*\"" fullword ascii
    $s2 = "pact@F" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}