rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aWlu0Qk_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aWlu0Qk_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5da91a9dc65808eec98f6343aa0a5fc2a9152b0c12ebc0428bc5463f34ecadb"

  strings:
    $s1 = "miCO>@4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}