rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7dfbd4d1c973ccf9c065be6441320c026cceb02bc0b3450616fc643931dde334"

  strings:
    $s1 = "yor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}