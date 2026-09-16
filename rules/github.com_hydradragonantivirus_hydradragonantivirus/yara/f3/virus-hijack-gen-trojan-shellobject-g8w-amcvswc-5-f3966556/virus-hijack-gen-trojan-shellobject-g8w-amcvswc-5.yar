rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_amCvSwc_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@amCvSwc_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f77d5281a3ee44a75c74816f42a6e84bee62cb78e78bcfc07acd525ae94cbf4"

  strings:
    $s1 = "^0University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}