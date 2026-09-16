rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbf76f1648c6a89e5dc064ce6d79538958a688397f8fca71ec8c2e4f0a4ab1f5"

  strings:
    $s1 = "q{What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}