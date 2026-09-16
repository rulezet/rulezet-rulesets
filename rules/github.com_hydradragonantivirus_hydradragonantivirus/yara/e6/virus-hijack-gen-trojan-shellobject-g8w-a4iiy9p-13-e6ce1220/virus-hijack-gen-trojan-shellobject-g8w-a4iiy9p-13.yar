rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_a4IIY9p_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@a4IIY9p_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf35b7fb8a30476b87504d26b0d02479e5b22b9652283229a2d62c2773af387e"

  strings:
    $s1 = "|Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}