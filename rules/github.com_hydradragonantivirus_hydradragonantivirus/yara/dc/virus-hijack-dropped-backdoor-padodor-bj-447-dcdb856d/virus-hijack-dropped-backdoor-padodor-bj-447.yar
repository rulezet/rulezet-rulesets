rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_447 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_447.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "221a8989588600dbe3cb5a2a435b37df23e359e0f911cf8fc882ca99c8c59507"

  strings:
    $s1 = "o`yEEL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}