rule Virus_Hijack_Backdoor_Hangup_B_140 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_140.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b42c844e121d5aac447d404fe51a179740e576689f585e70dd3783dac0c0821b"

  strings:
    $s1 = "eETrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}