rule Virus_Hijack_Gen_Trojan_ShellObject__WZ_aCIJdog_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@WZ@aCIJdog_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d5fad0f9f7f23c25e61a69fcff0a15cea7e668bdeb5ba42bc5b78ec90afcd6f"

  strings:
    $s1 = "Q`KnEe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}