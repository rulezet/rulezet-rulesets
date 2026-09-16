rule Virus_Hijack_GenPack_Backdoor_Hangup_B_70 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_70.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "425098f44462175c10259de927ca05036044c446fc09e2a32dd852cad0230a27"

  strings:
    $s1 = "|create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}