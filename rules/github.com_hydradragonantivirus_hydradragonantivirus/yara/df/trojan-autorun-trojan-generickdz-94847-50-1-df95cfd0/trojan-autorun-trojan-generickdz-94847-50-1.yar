rule Trojan_Autorun_Trojan_GenericKDZ_94847_50_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_50_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c21710924f9524cacd754e42d6762bf9c3370a8916f80851284cea933fc17865"

  strings:
    $s1 = "STthat party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}