rule Virus_Hijack_Gen_Variant_Graftor_639328 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Graftor.639328.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1117be735238fcea9cfc4bdcde64d9a0f07c240075facc570cc1de5e1df04481"

  strings:
    $s1 = "kernel)V6" fullword ascii
    $s2 = "p@gram {!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}