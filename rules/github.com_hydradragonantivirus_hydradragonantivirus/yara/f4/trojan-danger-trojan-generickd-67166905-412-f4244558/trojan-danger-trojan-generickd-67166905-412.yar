rule Trojan_Danger_Trojan_GenericKD_67166905_412 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_412.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52a5e97724d3fbf4ad67ff5d7681745a9287d1f9f01898d461e8caf5b3f53ea7"

  strings:
    $s1 = "//////////////////////////////Visual Studio Installer.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}