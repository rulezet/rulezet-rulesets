rule Virus_Sysbot_Trojan_GenericKD_71671752_29_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f4dc5c89721bb972beb619aab6d3767c03b12d102523a12d16df7d36c24ed75"

  strings:
    $s1 = "[computer]" fullword wide
    $s2 = "no more moves" fullword wide
    $s3 = "{0} won! total point balance: {1}:{2} " fullword wide
    $s4 = "Another round?" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}