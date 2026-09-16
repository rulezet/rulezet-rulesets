rule Virus_Hijack_Gen_Variant_Razy_868088 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Razy.868088.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "797cb5471f6569c04b22637c9fb00ff6b084c464d7da38d7ed8cf938fc019cdd"

  strings:
    $s1 = "Semielision" fullword wide
    $s2 = "Serpentinic" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}