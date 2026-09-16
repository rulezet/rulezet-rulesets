rule Virus_Hijack_Gen_Trojan_ShellObject_v8Z_aeVeeJk_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v8Z@aeVeeJk_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64bb1b3d911d3ab787b79a54f554b565cbf7d4bcb3de919942053c2663a55b5e"

  strings:
    $s1 = "Flicks Training" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}