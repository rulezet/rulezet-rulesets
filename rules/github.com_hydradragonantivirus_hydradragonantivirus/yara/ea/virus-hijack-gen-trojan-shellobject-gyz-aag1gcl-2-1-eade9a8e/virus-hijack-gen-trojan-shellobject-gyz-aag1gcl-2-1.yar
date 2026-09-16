rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aag1Gcl_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aag1Gcl_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bb54115cf74d0312e49934304a0944bd779c00054853db9a2bf57f08ddb5eda"

  strings:
    $s1 = "Irreverent" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}