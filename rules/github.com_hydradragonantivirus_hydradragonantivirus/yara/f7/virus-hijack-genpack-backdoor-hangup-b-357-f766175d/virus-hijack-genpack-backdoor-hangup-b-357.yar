rule Virus_Hijack_GenPack_Backdoor_Hangup_B_357 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_357.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f0f0479d844804ba3217f08b03395e156ac66b06ad2b598b9538cfb62c9fd8a"

  strings:
    $s1 = "W(software manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}