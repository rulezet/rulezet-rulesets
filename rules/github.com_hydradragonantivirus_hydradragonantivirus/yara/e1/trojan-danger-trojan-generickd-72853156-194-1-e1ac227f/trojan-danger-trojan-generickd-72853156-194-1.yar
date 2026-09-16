rule Trojan_Danger_Trojan_GenericKD_72853156_194_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_194_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a85bca1b5fdff5a666e6e174ba0f9506ee3c1fb412a77e970db3e27654a05b0d"

  strings:
    $s1 = "Copyright  Songhares" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}