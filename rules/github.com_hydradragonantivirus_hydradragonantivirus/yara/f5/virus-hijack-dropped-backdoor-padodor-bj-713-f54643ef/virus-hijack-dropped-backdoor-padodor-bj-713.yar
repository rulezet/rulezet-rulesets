rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_713 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_713.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aae4fd67d89b6f0bc82daee5f118a1a181f9af196ff446417f4da357412c4f8f"

  strings:
    $s1 = "6Vare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}