rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6f89ab3bb0ee27ad2b77f7dbf8b810e311086ca466a4d6ecaeb1011ab41060a"

  strings:
    $s1 = "@your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}