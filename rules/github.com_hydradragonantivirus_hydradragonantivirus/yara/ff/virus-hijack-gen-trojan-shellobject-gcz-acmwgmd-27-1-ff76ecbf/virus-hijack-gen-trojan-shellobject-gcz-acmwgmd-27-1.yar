rule Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_27_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_27_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4fd96f5919469374dfc8f551397d492f62e68297b3548b48b2f8e5cfe887250"

  strings:
    $s1 = "Skeeter" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}