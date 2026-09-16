rule Virus_Hijack_Gen_Trojan_ShellObject_C8Z_a0a9m9p_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8Z@a0a9m9p_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9669fdb7be82b47e95f556b74496f196309221ec194fd5d92f06fbf3a63d4890"

  strings:
    $s1 = "kSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}