rule Virus_Hijack_Gen_Trojan_ShellObject_u4Z_ay8bj9g_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u4Z@ay8bj9g_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37a5e04d35e198c0bb570e35db3d17d4bee598aab34632eccbf060ddbc352f8f"

  strings:
    $s1 = "Internal Compiler Bug: No runtime type matcher." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}