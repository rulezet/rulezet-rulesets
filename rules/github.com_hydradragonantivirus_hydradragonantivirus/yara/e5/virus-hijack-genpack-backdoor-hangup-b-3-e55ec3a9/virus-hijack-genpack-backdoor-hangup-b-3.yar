rule Virus_Hijack_GenPack_Backdoor_Hangup_B_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "515f497d6a7f333f19873e073a71c62fb00b99df710bc104d94292ff1c1a738b"

  strings:
    $s1 = "?software manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}