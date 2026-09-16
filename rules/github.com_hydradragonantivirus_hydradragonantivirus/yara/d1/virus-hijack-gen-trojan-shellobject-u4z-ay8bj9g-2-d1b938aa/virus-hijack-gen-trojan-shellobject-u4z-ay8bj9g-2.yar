rule Virus_Hijack_Gen_Trojan_ShellObject_u4Z_ay8bj9g_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u4Z@ay8bj9g_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfa490015173fd6d7a7d10a7418ff539877a6adb684a570552cbe667f8af401c"

  strings:
    $s1 = "j must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}