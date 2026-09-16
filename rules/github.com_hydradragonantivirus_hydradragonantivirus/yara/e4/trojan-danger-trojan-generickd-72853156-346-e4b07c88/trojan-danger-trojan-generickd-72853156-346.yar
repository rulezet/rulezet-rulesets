rule Trojan_Danger_Trojan_GenericKD_72853156_346 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_346.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4baee5ea59c5de4dfaaba5421440163ee53ec7a7ec81c01d7723466d090db88f"

  strings:
    $s1 = "crIER);" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}