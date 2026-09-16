rule Virus_Danger_Trojan_Agent_DQQO_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.Agent.DQQO_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bd870ebe211e17c38940439e3903169581707f25e6e26368c53ebce60f1683c"

  strings:
    $s1 = "Ruby 3.2.2 API Reference.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}