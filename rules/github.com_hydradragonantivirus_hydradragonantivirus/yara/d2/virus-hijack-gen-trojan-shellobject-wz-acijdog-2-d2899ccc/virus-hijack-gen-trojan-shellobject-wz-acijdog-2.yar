rule Virus_Hijack_Gen_Trojan_ShellObject__WZ_aCIJdog_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@WZ@aCIJdog_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "129f5e58b0c6989c2a508122841c4fd36aa7b709e4f1d787002e5eaa90d21d8c"

  strings:
    $s1 = "4Ffunctionality of the programs. You have 30 days from the delivery date to evaluate these programs. If you decide to use any" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}