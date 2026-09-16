rule Virus_Hijack_Trojan_Agent_DQQO_55 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_55.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "605634c874fbe7675d80ee298c5cfbf4b01275d3e4a443782703b25a44383825"

  strings:
    $s1 = "dautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}