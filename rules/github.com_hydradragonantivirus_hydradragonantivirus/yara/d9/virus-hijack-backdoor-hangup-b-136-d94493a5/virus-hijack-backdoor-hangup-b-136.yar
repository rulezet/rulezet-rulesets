rule Virus_Hijack_Backdoor_Hangup_B_136 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_136.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d12ccdd777b79fb543913ec6d492e2c831da459083ff25b2585f9cdf7809cc41"

  strings:
    $s1 = "icreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}