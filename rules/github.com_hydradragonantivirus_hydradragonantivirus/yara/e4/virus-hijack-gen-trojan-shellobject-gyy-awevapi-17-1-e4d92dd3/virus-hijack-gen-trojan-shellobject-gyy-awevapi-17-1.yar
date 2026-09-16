rule Virus_Hijack_Gen_Trojan_ShellObject_gyY_aWevApi_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyY@aWevApi_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2ae138c21045bcf804cddc457ce7cf60af0358211aaa0160d382701d35416ef"

  strings:
    $s1 = "Alienation" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}