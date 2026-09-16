rule Trojan_Danger_Trojan_GenericKD_72853156_112_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_112_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "219e44ebfe2477f04427a7cf1ef7c8618182afad010dfea9261337146f499cb4"

  strings:
    $s1 = "Shell lA" fullword ascii
    $s2 = "Computer`q" fullword ascii
    $s3 = "Progra Document" fullword wide
    $s4 = "flash " fullword wide
    $s5 = "SIzY)4" fullword ascii
    $s6 = "0Park Arena, Komaki, Aichi, Japan, 12. vacant WBO" fullword wide
    $s7 = "A kip is a non-SI unit of force. It equals 1000 pounds-force, used primarily by American architects and engineers to measure eng" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}