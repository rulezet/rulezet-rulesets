rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aag1Gcl_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aag1Gcl_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df4d86709a3dd47532058ef218f99a1df0094bf7b2a8eeadf5320dc87aec563a"

  strings:
    $s1 = "Prizable" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}