rule Virus_Sysbot_Trojan_GenericKD_71671752_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5007b414af5786cc24fc5733b70827d41a93d3ed4ab7fc8a7adfad566b51e7f3"

  strings:
    $s1 = "sH6a<lANT*C9" fullword ascii
    $s2 = "x]vasE" fullword ascii
    $s3 = "caAM&L7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}