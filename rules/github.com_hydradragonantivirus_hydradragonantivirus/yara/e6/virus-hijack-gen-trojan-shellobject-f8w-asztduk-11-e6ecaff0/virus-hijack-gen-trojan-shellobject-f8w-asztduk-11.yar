rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34f6978db1c301af96945586dff8e173f1aee8344c0d2c3315ffa8ac3dbd3029"

  strings:
    $s1 = ":or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}