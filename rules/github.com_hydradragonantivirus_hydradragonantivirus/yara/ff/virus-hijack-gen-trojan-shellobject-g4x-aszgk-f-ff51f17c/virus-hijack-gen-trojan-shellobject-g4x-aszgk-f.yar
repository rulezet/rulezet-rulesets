rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f10fa6797ab2e555e6a43c555100b9a8d334ddf8b01ff136edde14747311db1"

  strings:
    $s1 = "WinG`R@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}