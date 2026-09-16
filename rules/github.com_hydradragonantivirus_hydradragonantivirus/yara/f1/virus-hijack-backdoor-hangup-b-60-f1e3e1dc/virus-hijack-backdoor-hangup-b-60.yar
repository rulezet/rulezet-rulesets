rule Virus_Hijack_Backdoor_Hangup_B_60 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_60.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "878aa31f01c9a73b2f8e63dc6edf1109baec2e66f75a20dec11c0b7be366dfa3"

  strings:
    $s1 = "]SaDe;" fullword ascii
    $s2 = "H)SaMp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}