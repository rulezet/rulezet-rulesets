rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_a0a9m9p_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4f88889c490818b7df243b52b283d116f095bf51667ab66ce09d77e765e3d37"

  strings:
    $s1 = "yDSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}