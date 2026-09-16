rule Virus_Hijack_GenPack_Backdoor_Hangup_B_339 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_339.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d41d6c02a90a0dd441bb950788604a34811330a065943724f278fa5b39bad37f"

  strings:
    $s1 = "cof the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}