rule Virus_Hijack_Gen_Trojan_ShellObject_WyZ_aWELKOd_27 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.WyZ@aWELKOd_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f849093ac8f250e8c830f8d8f92e93207deb232cd85e07a52bf6004bdf49fcf"

  strings:
    $s1 = "-A]ENAM`O" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}