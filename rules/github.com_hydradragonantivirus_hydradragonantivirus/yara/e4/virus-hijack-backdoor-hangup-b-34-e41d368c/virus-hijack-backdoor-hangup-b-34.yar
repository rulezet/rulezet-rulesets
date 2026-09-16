rule Virus_Hijack_Backdoor_Hangup_B_34 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_34.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d2633e368bc0a9eb6d71d8ba729ab7b44d05d2b0a6ef23fbb51aa8eb8757408"

  strings:
    $s1 = "eEcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}