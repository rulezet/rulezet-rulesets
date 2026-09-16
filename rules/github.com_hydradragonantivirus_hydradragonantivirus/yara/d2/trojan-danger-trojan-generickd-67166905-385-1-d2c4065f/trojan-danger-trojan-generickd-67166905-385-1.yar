rule Trojan_Danger_Trojan_GenericKD_67166905_385_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_385_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "285876526894fa3e0c8fd67b69dbd4318afad131cac8504b38c36ae95953dbab"

  strings:
    $s1 = "ABLE:+OJ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}