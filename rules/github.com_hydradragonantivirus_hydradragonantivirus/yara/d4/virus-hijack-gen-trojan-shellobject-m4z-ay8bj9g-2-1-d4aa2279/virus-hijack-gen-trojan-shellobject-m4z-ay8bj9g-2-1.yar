rule Virus_Hijack_Gen_Trojan_ShellObject_m4Z_ay8bj9g_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m4Z@ay8bj9g_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0043b63cd7d0ce26b27cb1bfe931b3a37be9a262d09875e7cb90c2ab8eeb229"

  strings:
    $s1 = "tIZA@J" fullword ascii
    $s2 = "A)wIme" fullword ascii
    $s3 = "0%K)BlAW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}