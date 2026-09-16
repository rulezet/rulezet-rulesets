rule Virus_Hijack_GenPack_Backdoor_Hangup_B_126 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_126.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c04b81a06a68f94883f5e888a308ed51eaff62b16d935674c6bad45df8e83c64"

  strings:
    $s1 = "`the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}