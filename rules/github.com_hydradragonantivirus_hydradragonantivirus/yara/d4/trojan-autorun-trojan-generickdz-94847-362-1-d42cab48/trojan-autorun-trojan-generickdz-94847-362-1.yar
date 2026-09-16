rule Trojan_Autorun_Trojan_GenericKDZ_94847_362_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_362_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7b0e9be85d14fb2cb2164ffb2fb234a8905a5406463efade6a450e534808f07"

  strings:
    $s1 = "Aorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}