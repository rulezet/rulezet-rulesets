rule Virus_Hijack_Backdoor_Hangup_B_118 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_118.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9135d3a2df6a4b6e7aca2cbb7eac81b6f03b7c85998c40d0b30710c69c42a63a"

  strings:
    $s1 = "2Byour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}