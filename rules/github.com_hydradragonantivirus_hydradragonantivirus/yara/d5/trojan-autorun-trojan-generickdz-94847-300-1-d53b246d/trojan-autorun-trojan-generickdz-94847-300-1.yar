rule Trojan_Autorun_Trojan_GenericKDZ_94847_300_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_300_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70d0d01b6bb1a5673ce33730391f71232628adaa31b0507aa5ca361938274a82"

  strings:
    $s1 = "h2Orders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}