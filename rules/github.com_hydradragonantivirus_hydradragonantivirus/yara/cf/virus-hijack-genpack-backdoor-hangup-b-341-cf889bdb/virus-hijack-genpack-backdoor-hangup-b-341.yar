rule Virus_Hijack_GenPack_Backdoor_Hangup_B_341 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_341.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e715f41ea47cb58b5a4d2b4143fdaa4497c7859e0b9c9b3f5044fbac1c6a50d6"

  strings:
    $s1 = ",create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}