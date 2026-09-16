rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5691b01ee989826cd262b7d7b9f2eb5ff01adc8e44f6c135da108fa45dca7bf5"

  strings:
    $s1 = ",or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}