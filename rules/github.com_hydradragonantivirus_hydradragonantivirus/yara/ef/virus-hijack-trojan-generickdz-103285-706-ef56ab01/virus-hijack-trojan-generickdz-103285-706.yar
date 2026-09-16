rule Virus_Hijack_Trojan_GenericKDZ_103285_706 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_706.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ed8a9ebeeb72b24e1cc2116b9f228e894c3fc030479e51a30cd3222a353ca71"

  strings:
    $s1 = "ySubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}