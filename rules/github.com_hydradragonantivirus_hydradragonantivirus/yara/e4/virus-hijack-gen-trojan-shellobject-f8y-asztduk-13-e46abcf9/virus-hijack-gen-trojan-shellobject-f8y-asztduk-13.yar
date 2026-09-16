rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63f19595796f2cfc3a16bdc26855e03426f03d7a3342867985f0b64659789fac"

  strings:
    $s1 = "Eor service that is subject to a discount or a pr" fullword ascii
    $s2 = "miny&On" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}