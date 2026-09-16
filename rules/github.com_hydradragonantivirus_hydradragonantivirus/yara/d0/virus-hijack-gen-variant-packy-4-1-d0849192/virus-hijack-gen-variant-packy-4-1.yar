rule Virus_Hijack_Gen_Variant_Packy_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Packy.4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3a848fc1214047c06b3167cd4d11f960d9725b01a4117b10ff0dff8e7d095a9"

  strings:
    $s1 = "akinesia" fullword wide
    $s2 = "Roundwood" fullword wide
    $s3 = "Grison" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}