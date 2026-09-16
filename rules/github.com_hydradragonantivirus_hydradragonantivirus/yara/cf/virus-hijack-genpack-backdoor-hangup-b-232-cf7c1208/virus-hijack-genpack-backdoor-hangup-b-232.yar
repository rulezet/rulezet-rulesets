rule Virus_Hijack_GenPack_Backdoor_Hangup_B_232 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_232.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62a78cc1c0f4e66b7d1798acf96bfdd130b52ea86ea69fff72f893adb59a7678"

  strings:
    $s1 = "tuw{coSt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}