rule Virus_Hijack_Gen_Trojan_ShellObject_PCZ_aSQ1jei_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aSQ1jei_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b741088a269be340e257ceff3d3edf63ecc86b71c29cf7f230a3882ed8b7617"

  strings:
    $s1 = "N!raFF" fullword ascii
    $s2 = "N~uW<oAry" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}