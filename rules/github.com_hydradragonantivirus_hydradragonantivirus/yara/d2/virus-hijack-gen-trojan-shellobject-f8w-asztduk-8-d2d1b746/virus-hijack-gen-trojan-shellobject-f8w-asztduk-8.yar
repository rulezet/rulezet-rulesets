rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05e45db101e274f8436d37c1bbffb28e1872ba081f639688c1d52abf4b579721"

  strings:
    $s1 = "8or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}