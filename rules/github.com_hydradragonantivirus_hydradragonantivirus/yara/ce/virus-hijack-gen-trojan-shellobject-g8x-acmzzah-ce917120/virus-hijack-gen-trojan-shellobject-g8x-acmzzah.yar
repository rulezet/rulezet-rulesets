rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCMzZah {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCMzZah.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "575404859c372b5c0b6423022f6856f15f3b12c38f18ae1c0aad552da45eb1db"

  strings:
    $s1 = "W,orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}