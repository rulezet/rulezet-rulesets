rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abfbd67b85c91592b94905e9ce1c57eb9a2c9b12c07b1594c4553fbf51e3308f"

  strings:
    $s1 = "iWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}