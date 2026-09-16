rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_264_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_264_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42bfe599a42e09e34da50b1fc034602cc4bfd7e56bd0a5781077a5359d679d3c"

  strings:
    $s1 = "BRAd<F" fullword ascii
    $s2 = "ORAd<Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}