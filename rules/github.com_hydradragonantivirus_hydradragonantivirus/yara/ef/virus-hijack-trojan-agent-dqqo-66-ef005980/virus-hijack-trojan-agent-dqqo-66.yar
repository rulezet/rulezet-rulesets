rule Virus_Hijack_Trojan_Agent_DQQO_66 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_66.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7addae2d430f6a1d930bf712fea9a496ee01668d4541eb9c4829802b4684caa"

  strings:
    $s1 = "ANtU}Kp" fullword ascii
    $s2 = ")MoFF?F" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}