rule Virus_Hijack_Trojan_GenericKDZ_105924_387_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_387_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbe664565e03ec31683f11561ea9b00a1f8614c94a10bd82a9cc21277422d5fd"

  strings:
    $s1 = "stUM$kj" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}