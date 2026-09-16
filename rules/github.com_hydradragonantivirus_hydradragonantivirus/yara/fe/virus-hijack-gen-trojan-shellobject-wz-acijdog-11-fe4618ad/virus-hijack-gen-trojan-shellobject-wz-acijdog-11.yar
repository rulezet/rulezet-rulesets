rule Virus_Hijack_Gen_Trojan_ShellObject__WZ_aCIJdog_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@WZ@aCIJdog_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20c6a869d558f9c070f4f62c2e1def5676b09e9afb8989c6c10f51614a7b37f1"

  strings:
    $s1 = "kfunctionality of the programs. You have 30 days from the delivery date to evaluate these programs. If you decide to use any" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}