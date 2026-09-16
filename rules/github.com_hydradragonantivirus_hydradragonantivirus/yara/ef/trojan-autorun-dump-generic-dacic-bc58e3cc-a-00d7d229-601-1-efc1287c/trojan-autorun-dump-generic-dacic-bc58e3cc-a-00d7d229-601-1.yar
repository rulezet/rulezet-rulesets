rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_601_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_601_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b22772268ecf39322bf31692440d6ffc94f6ea95c4497e74165fa23e6e51ed6"

  strings:
    $s1 = "vBsoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}