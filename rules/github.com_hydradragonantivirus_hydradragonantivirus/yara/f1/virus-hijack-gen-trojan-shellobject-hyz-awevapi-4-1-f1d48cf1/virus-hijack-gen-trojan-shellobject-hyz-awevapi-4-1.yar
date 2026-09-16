rule Virus_Hijack_Gen_Trojan_ShellObject_hyZ_aWevApi_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.hyZ@aWevApi_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da42ef860d8e80d50c79671d7c32bd6ca375d557287af9b2e24e521915968fea"

  strings:
    $s1 = "Error Code Is:%d" fullword ascii
    $s2 = "%s Error!" fullword ascii
    $s3 = "Rich`l]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}