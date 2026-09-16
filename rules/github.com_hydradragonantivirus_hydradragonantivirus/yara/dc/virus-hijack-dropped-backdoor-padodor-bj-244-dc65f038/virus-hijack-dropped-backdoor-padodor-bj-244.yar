rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_244 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_244.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a715470acb8b3dc7be4412c0c316793cf8bfb8b7b540f2e1d9c17b292b86bac6"

  strings:
    $s1 = "Sand services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}