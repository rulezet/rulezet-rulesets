rule Virus_Hijack_Gen_Trojan_ShellObject_q4Z_aqH1LVc_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q4Z@aqH1LVc_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c5860b9fdecee0f5348d8d89a14f99968ceb30e544e2f60f4d5b48340edefa4"

  strings:
    $s1 = "h>SuDs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}