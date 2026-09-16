rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_565 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_565.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08b9afde09ffc80faeb450476bf0e01cc8745ac22053e9e351bc8e907fd5f5fb"

  strings:
    $s1 = "*are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}