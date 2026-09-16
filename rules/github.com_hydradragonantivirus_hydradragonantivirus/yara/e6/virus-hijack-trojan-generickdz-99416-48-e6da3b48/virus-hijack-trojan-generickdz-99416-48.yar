rule Virus_Hijack_Trojan_GenericKDZ_99416_48 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_48.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6eaf03b29fc97f9e1dccd1313be0fca611edf2e13b3b1c503d2bda85f09bee3a"

  strings:
    $s1 = "boBa%=" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}