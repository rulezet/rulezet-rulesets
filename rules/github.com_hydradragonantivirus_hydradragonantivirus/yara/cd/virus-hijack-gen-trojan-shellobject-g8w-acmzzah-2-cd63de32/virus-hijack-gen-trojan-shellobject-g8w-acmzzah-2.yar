rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aCMzZah_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aCMzZah_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "320f46aa1d1ed3209cbb153186347550b77c99b7e07e8cbacd790c81d7645103"

  strings:
    $s1 = "=orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}