rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_11_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4dccd1b9d8294f96e8c8b4422eb4a6d19a5ba02753d6738c18dab60157b6430"

  strings:
    $s1 = "!of the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}