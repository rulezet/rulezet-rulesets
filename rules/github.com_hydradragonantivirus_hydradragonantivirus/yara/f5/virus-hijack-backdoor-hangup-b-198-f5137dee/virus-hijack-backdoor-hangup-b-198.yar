rule Virus_Hijack_Backdoor_Hangup_B_198 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_198.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "898b3c0b40412b0fedf6752602b99ef360ce4ed0246cd3ad64205ca5d2174a63"

  strings:
    $s1 = "`the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}