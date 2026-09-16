rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2822a4f8c387b886cd1923d67a2ad5f71977e7e54e95452e990a073f4f0693be"

  strings:
    $s1 = "jor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}