rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aq5b2kh_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aq5b2kh_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a2607a9af335d645a4521b6b8ae4c0df096637529925a748d3ca0b74f97ead7"

  strings:
    $s1 = "Office Telemetry Dashboard" fullword wide
    $s2 = "@{Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}