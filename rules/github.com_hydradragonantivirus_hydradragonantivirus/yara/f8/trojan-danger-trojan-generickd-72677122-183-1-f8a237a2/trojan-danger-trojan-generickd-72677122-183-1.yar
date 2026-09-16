rule Trojan_Danger_Trojan_GenericKD_72677122_183_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_183_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0000206548be7d56ea269c4b6a4fe052303191e51403ac54d9bd58af306b8211"

  strings:
    $s1 = "4>ForK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}