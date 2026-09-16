rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_415 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_415.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5495ebe5f83d12a22908341db78b98e9ab9c3f2fc00777a10ca0502c7745542"

  strings:
    $s1 = "Rare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}