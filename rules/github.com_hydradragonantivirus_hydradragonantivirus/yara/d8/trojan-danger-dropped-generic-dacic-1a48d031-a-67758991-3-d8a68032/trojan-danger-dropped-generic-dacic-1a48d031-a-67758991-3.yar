rule Trojan_Danger_Dropped_Generic_Dacic_1A48D031_A_67758991_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Dropped.Generic.Dacic.1A48D031.A.67758991_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47c520e14e1f4b7c6dfec74ba0b56f47d6f855fe32cae4e0086669f328df6e53"

  strings:
    $s1 = "PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 85 Stepping 7, GenuineIntel" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}