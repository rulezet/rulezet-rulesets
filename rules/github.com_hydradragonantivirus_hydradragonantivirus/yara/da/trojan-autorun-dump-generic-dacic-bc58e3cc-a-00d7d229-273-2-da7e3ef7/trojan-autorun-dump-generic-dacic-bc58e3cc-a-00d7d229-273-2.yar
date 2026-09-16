rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_273_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_273_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d926f7f14556e0fcbf2bf4af5df95dd23f8dd855ef09fe3f1dd6b8978d26488"

  strings:
    $s1 = "vALL{AX" fullword ascii
    $s2 = "bOrtZ>" fullword ascii
    $s3 = "S!PLaN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}