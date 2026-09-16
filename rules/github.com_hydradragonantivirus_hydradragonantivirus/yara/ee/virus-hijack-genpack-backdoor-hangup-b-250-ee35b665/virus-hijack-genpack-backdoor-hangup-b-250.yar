rule Virus_Hijack_GenPack_Backdoor_Hangup_B_250 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_250.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df3dc0474716f1e1d94749edeae33d64b8021cb8da82e896adfafb71a21bad26"

  strings:
    $s1 = "&1the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}