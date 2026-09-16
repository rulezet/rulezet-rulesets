rule Trojan_Danger_Generic_Dacic_1A7FA519_A_A6538CDA_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.A6538CDA_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e1363089b547a31394c88946a39691b8887cd49b9082cfe7a59db25749a8f10"

  strings:
    $s1 = ".k(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii
    $s2 = ".k(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}