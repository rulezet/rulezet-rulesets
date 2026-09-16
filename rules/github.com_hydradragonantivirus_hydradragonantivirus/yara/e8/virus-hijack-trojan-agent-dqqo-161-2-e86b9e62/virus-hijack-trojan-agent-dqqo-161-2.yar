rule Virus_Hijack_Trojan_Agent_DQQO_161_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_161_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "001895509f2f6f822fff56810b82483427ba8e5fbe730412d842b82737861264"

  strings:
    $s1 = "if exist \"%s\" goto runagain" fullword ascii
    $s2 = "Media PlayGCO" fullword ascii
    $s3 = "56,golf u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}