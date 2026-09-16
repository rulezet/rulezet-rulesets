rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_258_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_258_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e317bb8f333ffec8505d17acf6f62eae54f9ce0cb85960449f147f3ca70457a"

  strings:
    $s1 = "local!clr-namespace:TicTacToe.GameViews" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}