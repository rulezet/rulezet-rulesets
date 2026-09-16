rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_226_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_226_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67a45d2373620eefb41057a76a363cdcc8d8715701809fdf6c25594d58719bee"

  strings:
    $s1 = ";WHAT[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}