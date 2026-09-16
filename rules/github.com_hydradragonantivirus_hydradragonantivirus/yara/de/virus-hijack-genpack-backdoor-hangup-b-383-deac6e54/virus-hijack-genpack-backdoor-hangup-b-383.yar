rule Virus_Hijack_GenPack_Backdoor_Hangup_B_383 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_383.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e77089b55600347fd9dfcbe90ecc8a69cf150142ec81fe3bb5b48b05468a524c"

  strings:
    $s1 = "SGTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}