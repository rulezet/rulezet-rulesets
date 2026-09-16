rule Virus_Hijack_Gen_Trojan_ShellObject_p8W_a8ws3Fk_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8W@a8ws3Fk_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db515dc8af807f7b9a7641da4892f06e514a0640ba377812ac504fe6c48c6f63"

  strings:
    $s1 = "CORE;5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}