rule Virus_Sysbot_Trojan_GenericKDZ_94659 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKDZ.94659.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f1fd33ce4baf934e239eec864a129d665711b427ac16782cf86657fd73d9996"

  strings:
    $s1 = "ly saved ac" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}