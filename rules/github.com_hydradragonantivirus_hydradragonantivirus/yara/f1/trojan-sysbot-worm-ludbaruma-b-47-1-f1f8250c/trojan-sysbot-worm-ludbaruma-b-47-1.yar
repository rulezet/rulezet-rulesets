rule Trojan_Sysbot_Worm_Ludbaruma_B_47_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Worm.Ludbaruma.B_47_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9319b65df7d7caeb1d2a59f845d78e0f41c937fc9296ebbcae44cbd373831477"

  strings:
    $s1 = "Microsoft Office Diagnostics.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}