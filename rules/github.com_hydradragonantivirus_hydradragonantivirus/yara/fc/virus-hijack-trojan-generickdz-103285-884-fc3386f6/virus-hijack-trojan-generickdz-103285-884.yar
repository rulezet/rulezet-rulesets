rule Virus_Hijack_Trojan_GenericKDZ_103285_884 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_884.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97cf5c327ca75ff994105612e0c4bf5c4d0d90ee10139649208d3f5827ffa779"

  strings:
    $s1 = "*Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}