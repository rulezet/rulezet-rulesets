rule Trojan_Danger_Trojan_GenericKD_67166905_113_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_113_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c207d576731454f9e38651b0c029c4c531ae26a1baa855924fd3d21225a287da"

  strings:
    $s1 = "7!Brat" fullword ascii
    $s2 = "><*BhOY)^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}