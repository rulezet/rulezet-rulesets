rule Virus_Sysbot_Trojan_GenericKD_71671752_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f45dec8b1e8cb601c8a4d447cd1d7bf28ce71ffc3117b6fc4d3b46d3928647a0"

  strings:
    $s1 = "#w}HARM" fullword ascii
    $s2 = "\"?tROW" fullword ascii
    $s3 = "HuSE, " fullword ascii
    $s4 = "trig$I" fullword ascii
    $s5 = "|@lALo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}