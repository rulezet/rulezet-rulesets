rule Trojan_Autorun_Trojan_GenericKD_72517131_206_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_206_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de5df7cbae8fe4f15b59f0701222acde700b8da5736ead45bd94e9aebaa46d32"

  strings:
    $s1 = "ZUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}