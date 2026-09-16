rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_200_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_200_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55b2592838fa6ee09177a996a986a6c566f45deb692116488b85f180dc1aa667"

  strings:
    $s1 = "ViLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}