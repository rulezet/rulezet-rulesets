rule Virus_Hijack_Backdoor_Hangup_B_236 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_236.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "031a7439c7dc56d26811ac948ddc9187da86af014545ba4e76576e8ec9da90c1"

  strings:
    $s1 = "jTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}