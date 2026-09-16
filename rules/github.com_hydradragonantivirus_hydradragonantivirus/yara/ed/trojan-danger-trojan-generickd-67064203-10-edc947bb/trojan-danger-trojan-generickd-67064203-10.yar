rule Trojan_Danger_Trojan_GenericKD_67064203_10 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67064203_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6e808e2e547e76c2637aa893a4a332b5d01f2eed4f15b77f4d65f8a33f8d3a4"

  strings:
    $s1 = "Microsoft Office PowerPoint 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}