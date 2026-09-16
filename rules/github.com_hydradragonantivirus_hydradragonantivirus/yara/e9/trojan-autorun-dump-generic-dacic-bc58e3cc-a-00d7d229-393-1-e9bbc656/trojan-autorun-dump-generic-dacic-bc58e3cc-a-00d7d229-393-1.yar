rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_393_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_393_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6adc064852950faf8cb17d958e36c9719ddb5edc0085bbafeb06812ec208121"

  strings:
    $s1 = "FGiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}