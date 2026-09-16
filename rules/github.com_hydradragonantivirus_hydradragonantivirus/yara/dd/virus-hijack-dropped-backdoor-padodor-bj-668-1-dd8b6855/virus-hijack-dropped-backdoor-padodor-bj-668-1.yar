rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_668_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_668_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9638143d0f44d2c2a4074fa805935c9c5fbf4e7b2956a2ee97cb1b12d5e5cf70"

  strings:
    $s1 = "slIm]lZ" fullword ascii
    $s2 = "D`LERP" fullword ascii
    $s3 = "BAck]~" fullword ascii
    $s4 = "SnUG#K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}