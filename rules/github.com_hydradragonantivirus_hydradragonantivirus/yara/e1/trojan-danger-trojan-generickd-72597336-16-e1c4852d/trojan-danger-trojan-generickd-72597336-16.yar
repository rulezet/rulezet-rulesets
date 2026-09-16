rule Trojan_Danger_Trojan_GenericKD_72597336_16 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72597336_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45be39bf0fc3ae6c6c5747e3e5f1b0b70de46cddd8c90757b52862402a1ffbb0"

  strings:
    $s1 = "Event Viewer.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}