rule Virus_Hijack_GenPack_Backdoor_Hangup_B_309 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_309.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43da527e7a53364c8abc97ff7ce038d2f7ff02e31b6a3d02bdaa4d743f78bcbb"

  strings:
    $s1 = "Sto be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of this" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}