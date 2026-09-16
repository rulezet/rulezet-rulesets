rule Virus_Hijack_GenPack_Backdoor_Hangup_B_33 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_33.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b38b0c9133cc30d54769461bc73c3f22a37a08aa763b7260fab45600c8a619af"

  strings:
    $s1 = "Yvthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}