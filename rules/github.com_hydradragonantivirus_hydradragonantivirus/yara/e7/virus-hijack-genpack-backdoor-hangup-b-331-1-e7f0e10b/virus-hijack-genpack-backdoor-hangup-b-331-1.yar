rule Virus_Hijack_GenPack_Backdoor_Hangup_B_331_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_331_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a09d6ebdba1cca5e123d455805c2dcc90e1a1b1bb71b9d0966dc2fd1fd43b6bb"

  strings:
    $s1 = ",Reference Viewing Co" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}