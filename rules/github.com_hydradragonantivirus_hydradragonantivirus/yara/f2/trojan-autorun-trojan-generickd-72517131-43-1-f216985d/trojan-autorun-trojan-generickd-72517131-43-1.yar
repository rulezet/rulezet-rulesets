rule Trojan_Autorun_Trojan_GenericKD_72517131_43_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_43_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3639611ddd46647b650c47fc5ddc12a07fac11cc1aa05a1708903c7b09ed837d"

  strings:
    $s1 = "}4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}