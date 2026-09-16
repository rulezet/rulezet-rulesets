rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2f26e3af0d0607e6d6d9f591ff31455fc0ff2492797582e2751424fab4277af"

  strings:
    $s1 = "M?functionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}