rule Virus_Hijack_GenPack_Backdoor_Hangup_B_192 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_192.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4d5f25379e727e5c7cc8885808822040de680cf6b84da33cc8ad238aef952c7"

  strings:
    $s1 = "aof the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}