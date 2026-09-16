rule Trojan_Danger_Trojan_GenericKD_72304918_161_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_161_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10a20e54a8f216b756bfefe1f1d78f55fe5229277ea239e8f7e0ec8396518e7e"

  strings:
    $s1 = "RSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii
    $s2 = "o_,GaRe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}