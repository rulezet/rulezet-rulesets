rule Trojan_Autorun_Trojan_GenericKDZ_95048_14_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.95048_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8611d18dc359b83addbef7721a65cee368e1bb0eb7b558a2ca32b1a8970ae60d"

  strings:
    $s1 = "S&Orders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}