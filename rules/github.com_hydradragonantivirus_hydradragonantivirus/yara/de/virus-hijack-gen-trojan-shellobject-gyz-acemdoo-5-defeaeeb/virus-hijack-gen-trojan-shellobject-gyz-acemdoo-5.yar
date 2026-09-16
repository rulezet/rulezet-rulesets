rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aCEmdoo_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aCEmdoo_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4576106d85ed89fa69d0e1758a425203e2471540820a82e2a62dec872a31159a"

  strings:
    $s1 = "Datolite" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}