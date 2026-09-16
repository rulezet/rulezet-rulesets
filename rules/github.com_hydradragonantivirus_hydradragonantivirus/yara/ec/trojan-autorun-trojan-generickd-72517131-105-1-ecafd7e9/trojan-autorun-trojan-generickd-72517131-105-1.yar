rule Trojan_Autorun_Trojan_GenericKD_72517131_105_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_105_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ef58726a48ccee683d5401420714a78d2f7e8be73eaa91b726ac9e99f6e4a6b"

  strings:
    $s1 = "6User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}