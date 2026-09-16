rule Trojan_Danger_Trojan_GenericKD_72853156_392_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_392_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "907d2af09c275e1a3ae328d17728ec95a298047cababddd506ebcc5ac8fac833"

  strings:
    $s1 = "Pobs'I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}