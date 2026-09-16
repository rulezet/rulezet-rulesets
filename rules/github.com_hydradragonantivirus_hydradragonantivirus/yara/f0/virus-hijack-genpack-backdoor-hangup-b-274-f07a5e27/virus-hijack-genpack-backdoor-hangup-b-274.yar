rule Virus_Hijack_GenPack_Backdoor_Hangup_B_274 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_274.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d02bbdb5ebd2862c06fb900c1f0b10cad5ad7ec76e4ea379cd66c7b145238399"

  strings:
    $s1 = "[Jthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}