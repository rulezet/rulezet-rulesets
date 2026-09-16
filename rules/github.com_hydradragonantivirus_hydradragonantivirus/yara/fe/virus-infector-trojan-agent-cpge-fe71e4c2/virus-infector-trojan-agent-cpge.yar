rule Virus_Infector_Trojan_Agent_CPGE {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Trojan.Agent.CPGE.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e26dda0b2e905ee5ca8b255801bbaef320587eaf2ce199586a4b4d5ae53f9b0b"

  strings:
    $s1 = "Color@&B" fullword ascii
    $s2 = "Height,%B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}