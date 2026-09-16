rule Virus_Sysbot_Dump_Generic_Dialer_F020CCE3_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.F020CCE3_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee2af568e94caf62f314ae97c1b6d2e3b170a732c00812ee0d249a1a284761cb"

  strings:
    $s1 = "Like&\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}