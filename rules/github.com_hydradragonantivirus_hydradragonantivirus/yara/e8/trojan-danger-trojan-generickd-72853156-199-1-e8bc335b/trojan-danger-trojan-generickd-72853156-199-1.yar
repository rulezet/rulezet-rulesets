rule Trojan_Danger_Trojan_GenericKD_72853156_199_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_199_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e488e5b843db609ddb25385eddc0ffe9bfcd08fa54b5a6ace169de71698e5cf"

  strings:
    $s1 = "*,Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}