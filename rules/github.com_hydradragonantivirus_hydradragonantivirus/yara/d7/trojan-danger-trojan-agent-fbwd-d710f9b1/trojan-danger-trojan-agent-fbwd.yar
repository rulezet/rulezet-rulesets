rule Trojan_Danger_Trojan_Agent_FBWD {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Agent.FBWD.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dc7c16dd5d39630bfdd4a01eb528223ebf0a7ee9a022d473f9137cffe3a7284"

  strings:
    $s1 = "Virtual@L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}