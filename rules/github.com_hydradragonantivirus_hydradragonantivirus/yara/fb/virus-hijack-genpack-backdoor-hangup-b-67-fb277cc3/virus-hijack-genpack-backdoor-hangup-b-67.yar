rule Virus_Hijack_GenPack_Backdoor_Hangup_B_67 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_67.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4ec8b9c050b1aa5ccbaa5bff9b72ab4f2199226e64039b5f20c6532ccf5e2b8"

  strings:
    $s1 = "o2software manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}