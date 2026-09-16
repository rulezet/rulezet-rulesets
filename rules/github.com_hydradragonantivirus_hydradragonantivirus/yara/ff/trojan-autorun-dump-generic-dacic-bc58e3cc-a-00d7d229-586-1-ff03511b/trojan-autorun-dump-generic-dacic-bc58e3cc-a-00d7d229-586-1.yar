rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_586_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_586_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b667736e86e89c172d9109a48bbf67aca7fad257f467c4fb199da5ea8d997e08"

  strings:
    $s1 = "mTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}