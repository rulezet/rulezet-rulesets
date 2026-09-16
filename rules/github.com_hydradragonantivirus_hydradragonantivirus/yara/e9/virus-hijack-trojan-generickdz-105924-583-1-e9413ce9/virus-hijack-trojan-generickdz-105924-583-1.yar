rule Virus_Hijack_Trojan_GenericKDZ_105924_583_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_583_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2736758d541f54729a8ee2f8891d5184ee2656b0332f2d9c04e0f5c3d11e356"

  strings:
    $s1 = "6\"}torU" fullword ascii
    $s2 = "z]AlCo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}