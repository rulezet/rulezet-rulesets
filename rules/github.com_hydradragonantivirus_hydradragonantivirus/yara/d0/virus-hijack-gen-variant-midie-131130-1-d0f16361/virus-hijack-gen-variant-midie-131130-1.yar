rule Virus_Hijack_Gen_Variant_Midie_131130_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Midie.131130_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c128392b6d229b68e1766c41b81145d3000d4c5ea5c16effe99c5e2770cb710"

  strings:
    $s1 = "ramiferous" fullword wide
    $s2 = "Tattooment" fullword wide
    $s3 = "Gnathonize" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}