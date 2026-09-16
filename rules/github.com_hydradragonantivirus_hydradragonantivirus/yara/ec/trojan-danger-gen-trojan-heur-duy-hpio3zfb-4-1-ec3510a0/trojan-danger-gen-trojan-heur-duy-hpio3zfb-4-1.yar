rule Trojan_Danger_Gen_Trojan_Heur_duY_HPIO3zfb_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Trojan.Heur.duY@HPIO3zfb_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12bf313bb0fec057c2667527f61da4be606060ec637f1ddfdf7eda64757a2659"

  strings:
    $s1 = "ewRY]Mr<E8_fhX!I" fullword ascii
    $s2 = "-$BIrL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}