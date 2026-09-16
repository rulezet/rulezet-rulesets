rule Virus_Hijack_Gen_Trojan_ShellObject_D8W_aCma7ml_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.D8W@aCma7ml_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b69d7092de79dd9036b1c779fab54fd89d81c61e46657bdd1b572d0130de1e51"

  strings:
    $s1 = "7?ROBe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}