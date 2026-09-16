rule Trojan_Danger_Trojan_GenericKD_72304918_122_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_122_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0760c24849cc95291925bd19445c1ee09b207146655ab71cc1988d4ab006d50c"

  strings:
    $s1 = "neON#e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}