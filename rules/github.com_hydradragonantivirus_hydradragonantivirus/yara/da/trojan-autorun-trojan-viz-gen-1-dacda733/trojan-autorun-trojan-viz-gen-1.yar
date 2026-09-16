rule Trojan_Autorun_Trojan_VIZ_Gen_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.VIZ.Gen.1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86b9bd5c4f859a746e46917d430af03e750ad7593f205c7f6c65f1fc66c90e73"

  strings:
    $s1 = "<description>Narmertaria</description>" fullword ascii
    $s2 = "That program must be run under Win32" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}