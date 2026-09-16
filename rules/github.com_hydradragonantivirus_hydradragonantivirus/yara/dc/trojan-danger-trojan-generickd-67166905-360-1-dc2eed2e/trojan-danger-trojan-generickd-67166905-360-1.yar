rule Trojan_Danger_Trojan_GenericKD_67166905_360_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_360_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca7a7b2b33d3047f3328127dafe84d4f08ef47678ef6885711c4296dcda8d222"

  strings:
    $s1 = "hUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}