rule Virus_Hijack_Gen_Trojan_ShellObject_q4Z_aqH1LVc_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q4Z@aqH1LVc_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bce6da499749d8bd66787f05e61c94ee814d32b7ef137784d878bfaeff69b36d"

  strings:
    $s1 = "($hakU" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}