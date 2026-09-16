rule Virus_Hijack_GenPack_Backdoor_Hangup_B_252_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_252_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f430ab27641fd3a2c39ce346b7d230508655b18a62becee6043c8ae36c49187d"

  strings:
    $s1 = "2.1 Default RGB colour space " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}