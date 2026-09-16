rule Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b580e1dc74272b09af08610a1559859c1e9e53aadcbe82dd722ea61672c3c29a"

  strings:
    $s1 = "Platinize" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}