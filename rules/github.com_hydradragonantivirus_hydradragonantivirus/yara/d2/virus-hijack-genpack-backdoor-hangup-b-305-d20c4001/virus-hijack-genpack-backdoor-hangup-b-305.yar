rule Virus_Hijack_GenPack_Backdoor_Hangup_B_305 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_305.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9daef790a1bb0423d4cfb4a8296a9659e7b9d99f9e11e2080699556da81cc438"

  strings:
    $s1 = "DFthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}