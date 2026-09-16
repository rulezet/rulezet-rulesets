rule Trojan_Danger_Trojan_GenericKD_67166905_151_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_151_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "173c040ebcb0751d1da6fd02651c8aa9d1e66c21f8e36aa3eb8950ecacdaa139"

  strings:
    $s1 = "6NWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}