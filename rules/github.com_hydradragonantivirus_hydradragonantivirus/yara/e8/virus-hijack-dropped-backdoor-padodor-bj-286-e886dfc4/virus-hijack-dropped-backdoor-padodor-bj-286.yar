rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_286 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_286.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbf13710e2f156473abe1cddfdb32c689b623495474899cea504a36f8b27d3c8"

  strings:
    $s1 = "^and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}