rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_399_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_399_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4caa6522001702aeb2bb21a307789a4ba952b829265e91fcbd0901141f0c966"

  strings:
    $s1 = "Progra Document" fullword wide
    $s2 = "flash " fullword wide
    $s3 = "SIzY)4" fullword ascii
    $s4 = "0Park Arena, Komaki, Aichi, Japan, 12. vacant WBO" fullword wide
    $s5 = "A kip is a non-SI unit of force. It equals 1000 pounds-force, used primarily by American architects and engineers to measure eng" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}