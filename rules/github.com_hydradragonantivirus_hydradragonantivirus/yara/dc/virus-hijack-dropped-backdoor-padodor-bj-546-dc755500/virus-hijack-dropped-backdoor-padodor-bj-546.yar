rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_546 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_546.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f1bf0b5babe49ef5f25b8fa1df4c56f14a50ddeb5573797ad2993177652da49"

  strings:
    $s1 = "?are a part of the software and may not be used s" fullword ascii
    $s2 = "SoAk;l+" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}