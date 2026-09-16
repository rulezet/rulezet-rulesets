rule Trojan_Danger_Dropped_Generic_Dacic_1A48D031_A_67758991_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Dropped.Generic.Dacic.1A48D031.A.67758991_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e259d59b1adfb29cd20e8ba35dd3bbf52718d42db8fb2513f05cb508199e611f"

  strings:
    $s1 = "B!bOLE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}