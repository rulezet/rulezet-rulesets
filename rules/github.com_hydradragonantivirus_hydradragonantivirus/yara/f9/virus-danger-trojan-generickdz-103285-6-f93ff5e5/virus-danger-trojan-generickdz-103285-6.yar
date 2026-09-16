rule Virus_Danger_Trojan_GenericKDZ_103285_6 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b588f4bd001e3deb4084a6c57a5a2e19dfd543e3d7652339ada30b38ffc5fc0d"

  strings:
    $s1 = "QWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}