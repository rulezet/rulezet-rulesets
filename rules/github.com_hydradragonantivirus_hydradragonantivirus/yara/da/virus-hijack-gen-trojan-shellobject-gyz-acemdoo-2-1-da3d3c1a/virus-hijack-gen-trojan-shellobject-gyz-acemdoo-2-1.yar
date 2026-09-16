rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aCEmdoo_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aCEmdoo_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be45b009a66b1dc649e41e162cb99d0f74c97431d10ff4d136b16022b1d03c36"

  strings:
    $s1 = "Grapevine" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}