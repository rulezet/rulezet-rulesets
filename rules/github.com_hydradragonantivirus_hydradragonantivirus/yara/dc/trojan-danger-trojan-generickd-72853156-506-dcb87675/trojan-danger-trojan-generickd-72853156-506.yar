rule Trojan_Danger_Trojan_GenericKD_72853156_506 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_506.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a68173960d14d3fb012c255c17e613c32b0d7cd5e42c1bbcb942881e3a97092d"

  strings:
    $s1 = "Task Manager.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}