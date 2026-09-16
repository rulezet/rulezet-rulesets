rule Trojan_Danger_Trojan_Generic_36486627_10_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Generic.36486627_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4630717e8fd909273712034ec62e349a3923c3eec6876bb70131a5d96f883bac"

  strings:
    $s1 = "and/or running. With respect to the Customer Data Hub program, in determining the number `" fullword ascii
    $s2 = "5rmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}