rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ad0c83615576c3c2679401b5d6c479d87d68d290583abef727c3dc148a39b20"

  strings:
    $s1 = "por service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}