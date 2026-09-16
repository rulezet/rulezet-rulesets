rule Virus_Hijack_Gen_Trojan_ShellObject_ryZ_ayMBdto_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ryZ@ayMBdto_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df21ed1adf94f98e37cfce49a063a771fbfcb9c50d469dbdd6ea97c9d22bb9b4"

  strings:
    $s1 = "Copyrig}t (c) 1998 Hewlett-Packard Company" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}