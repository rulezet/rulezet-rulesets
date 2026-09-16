rule Virus_Hijack_Trojan_GenericKDZ_105924_605_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_605_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5faf492027072755a7ea68d83909110ecaad9e9d820cfbc8fe34b7bb4e6b238e"

  strings:
    $s1 = "k?bROd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}