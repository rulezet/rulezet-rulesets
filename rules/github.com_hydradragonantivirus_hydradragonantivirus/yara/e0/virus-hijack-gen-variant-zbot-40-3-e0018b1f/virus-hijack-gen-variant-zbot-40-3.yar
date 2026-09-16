rule Virus_Hijack_Gen_Variant_Zbot_40_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Zbot.40_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c31592f6c0e8b44eb4823a81699145e7913ea7ae007e30ac96070d321b1bce3e"

  strings:
    $s1 = "Monoammonium" fullword wide
    $s2 = "Gantsl" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}