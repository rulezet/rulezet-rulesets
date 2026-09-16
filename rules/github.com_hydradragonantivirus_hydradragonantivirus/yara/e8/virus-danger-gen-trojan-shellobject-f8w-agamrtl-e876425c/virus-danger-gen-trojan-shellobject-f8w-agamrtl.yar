rule Virus_Danger_Gen_Trojan_ShellObject_f8W_aGAMRTl {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.f8W@aGAMRTl.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e0452203fd2ac52a2a7261d83eb9c5b0575bb9706e837ae87f9171748c056f3"

  strings:
    $s1 = "V@vIVe>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}