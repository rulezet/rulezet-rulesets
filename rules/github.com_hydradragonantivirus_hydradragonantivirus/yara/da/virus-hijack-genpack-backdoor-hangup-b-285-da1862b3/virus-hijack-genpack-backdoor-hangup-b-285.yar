rule Virus_Hijack_GenPack_Backdoor_Hangup_B_285 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_285.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c06955b5dbc0f6e0149233ca943bd376b766a528deb0a62776bf286ba27ec2"

  strings:
    $s1 = "_~software manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}