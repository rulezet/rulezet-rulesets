rule Trojan_Autorun_Trojan_GenericKD_72517131_141_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_141_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1bf1268fa797f2e2e0da99d45dc566b95844cdf355dec8b6874fee3cdc1f13b"

  strings:
    $s1 = ".EUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}