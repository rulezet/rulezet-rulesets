rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d07c9f0887aee4b587ce4e3110a1c970de0d385a7babf3211bfc36c1e0bbdc37"

  strings:
    $s1 = "CADE!%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}