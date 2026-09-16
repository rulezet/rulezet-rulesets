rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCMzZah_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCMzZah_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9cdbe383be7bf2ae610a272e485879a97338c360ba1516040d89e86c998a1ad"

  strings:
    $s1 = "Whinge" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}