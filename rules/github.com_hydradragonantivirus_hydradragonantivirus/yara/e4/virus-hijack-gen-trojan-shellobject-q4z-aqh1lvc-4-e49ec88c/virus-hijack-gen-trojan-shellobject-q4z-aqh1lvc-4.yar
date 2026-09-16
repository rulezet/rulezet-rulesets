rule Virus_Hijack_Gen_Trojan_ShellObject_q4Z_aqH1LVc_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q4Z@aqH1LVc_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "805bac594c0dfc66edd63b38fd2cf730e2d3a4dda0c859a0ac15f7a352f6667e"

  strings:
    $s1 = "}]dUFF" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}