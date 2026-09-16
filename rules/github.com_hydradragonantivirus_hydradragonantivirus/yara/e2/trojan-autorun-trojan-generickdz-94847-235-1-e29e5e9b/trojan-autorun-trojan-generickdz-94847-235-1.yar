rule Trojan_Autorun_Trojan_GenericKDZ_94847_235_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_235_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b9bd377223308fdf1ef9c1b3b1ff12b57b026405b3e92db6f5fd448d0141150"

  strings:
    $s1 = "FUsc@Usc@Usc@Usc@Usc@Usc@Usc@Usc@Usc@Usc@Usc@Usc@Us" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}