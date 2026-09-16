rule Virus_Hijack_Gen_Trojan_ShellObject_gyY_aWevApi_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyY@aWevApi_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d20554ef8491d772f0552fa4964e1a2bc9d10ffa6c77ccdb7ef69f9bf83bed9b"

  strings:
    $s1 = "Summertide" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}