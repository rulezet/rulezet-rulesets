rule Virus_Hijack_GenPack_Backdoor_Hangup_B_122 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_122.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3446e4c2d1869b39d270082b4f2f4f8c90d8bf0e80bcdca1674817ab2a10f7c0"

  strings:
    $s1 = "@LoTA$o|A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}