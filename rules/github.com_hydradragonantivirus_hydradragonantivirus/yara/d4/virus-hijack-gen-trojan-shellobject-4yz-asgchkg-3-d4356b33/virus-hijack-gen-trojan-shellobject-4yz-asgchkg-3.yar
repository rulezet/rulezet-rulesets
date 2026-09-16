rule Virus_Hijack_Gen_Trojan_ShellObject_4yZ_aSgChKg_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.4yZ@aSgChKg_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e09d0acf22049ff197b4784d011226d4061cea32168062fe27556a70fe312177"

  strings:
    $s1 = "!>tATh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}