rule Virus_Autorun_Gen_Trojan_Backdoor2_dmHfaG9j7l {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Gen.Trojan.Backdoor2.dmHfaG9j7l.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85a314a739a63a709694e9d70e794e2b36aa1f78f3825769d5350fd0c13a36c3"

  strings:
    $s1 = "loup Gail" fullword ascii
    $s2 = "? deflate 1.2" fullword ascii
    $s3 = "IF EXIST" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}