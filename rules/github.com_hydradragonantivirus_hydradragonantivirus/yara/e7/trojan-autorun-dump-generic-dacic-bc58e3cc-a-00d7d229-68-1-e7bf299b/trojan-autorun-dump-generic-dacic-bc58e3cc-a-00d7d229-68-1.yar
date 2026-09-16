rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_68_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_68_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adab247b192dad039569b3d195740e21cda54932abd6ff87ec2eb63edaca624d"

  strings:
    $s1 = "repP;^A3;O\\06\\z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}