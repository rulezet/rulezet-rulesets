rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_aKo42Jj_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e056b9c01a8d01ac6060ada7f91ba4a0842b266cdc8c65ca7d9948f0e2e5c2e4"

  strings:
    $s1 = "GYVE{gp\"o" fullword ascii
    $s2 = "[HUll<h" fullword ascii
    $s3 = "Epic]<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}