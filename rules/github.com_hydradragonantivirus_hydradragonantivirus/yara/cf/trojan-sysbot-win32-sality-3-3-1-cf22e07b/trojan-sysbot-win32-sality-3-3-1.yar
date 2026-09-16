rule Trojan_Sysbot_Win32_Sality_3_3_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Win32.Sality.3_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b279b94663e5147c770076884f4a9c4809798be304c908e9cb68056dcc547190"

  strings:
    $s1 = "Microsoft Office Diagnostics.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}