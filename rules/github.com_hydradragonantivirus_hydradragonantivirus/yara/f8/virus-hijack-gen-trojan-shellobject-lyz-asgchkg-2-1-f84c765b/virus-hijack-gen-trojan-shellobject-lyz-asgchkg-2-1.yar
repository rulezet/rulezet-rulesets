rule Virus_Hijack_Gen_Trojan_ShellObject_lyZ_aSgChKg_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.lyZ@aSgChKg_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4735c390a294ca9a0bebb01976d920500c6f3d543ca8cac043a56deb7237713a"

  strings:
    $s1 = "spAD`^_" fullword ascii
    $s2 = "About ABCSeeFC" fullword ascii
    $s3 = "Checked`9D" fullword ascii
    $s4 = "TEaL<[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}