rule Virus_Hijack_Gen_Trojan_ShellObject_u4Z_ay8bj9g_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u4Z@ay8bj9g_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c0b6893d2b6c9206a7b2e76531792433c79a3d2199f3e038f4fec0a3ebb0f8f"

  strings:
    $s1 = ",Reference Viewing Con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}