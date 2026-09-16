rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_213_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_213_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5099c76c5594077a16a7f8d7908e16c94559d7e6af42c98bb086cc5efa0dfb18"

  strings:
    $s1 = "C_controlfp_s(((void *)0), 0x00010000, 0x00030000)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}