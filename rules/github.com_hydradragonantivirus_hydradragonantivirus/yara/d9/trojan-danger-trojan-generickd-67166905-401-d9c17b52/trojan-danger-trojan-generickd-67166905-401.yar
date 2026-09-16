rule Trojan_Danger_Trojan_GenericKD_67166905_401 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_401.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4b36986a8e3bb6ce068ce0d049cb7d4e45e7116e8bf5d31210796c63e9e1b0a"

  strings:
    $s1 = "System Information.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}