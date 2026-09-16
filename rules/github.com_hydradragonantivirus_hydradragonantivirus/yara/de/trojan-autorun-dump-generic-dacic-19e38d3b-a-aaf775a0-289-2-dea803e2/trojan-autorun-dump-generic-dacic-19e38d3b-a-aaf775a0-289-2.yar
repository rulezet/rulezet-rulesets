rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_289_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_289_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc71c390f89548a05cecb7eb1c45d574e4421001cb5bd519a623ff79a21d965e"

  strings:
    $s1 = "kULA#4" fullword ascii
    $s2 = "1<AFfA(" fullword ascii
    $s3 = "ATry%+" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}