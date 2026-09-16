rule Virus_Hijack_GenPack_Backdoor_Hangup_B_185 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_185.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3255a352ad2cbedfe5ab2c5c88f0a5070602d127cc8d8246daa17d087474ec1"

  strings:
    $s1 = "iof the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}