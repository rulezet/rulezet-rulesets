rule Virus_Hijack_Backdoor_Hangup_B_271_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_271_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e4a8304b9ea48f006c3e48269b0293a0a8d90f8bef6bd008c20c68c0c0eaee6"

  strings:
    $s1 = "Target directory is %s." fullword ascii
    $s2 = "Input directory is too large." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}