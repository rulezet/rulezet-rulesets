rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oG5if_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2418855741336d47956bc68ae20a3275a8aa3a60202db29e9f269645e17c56ed"

  strings:
    $s1 = "eRby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}