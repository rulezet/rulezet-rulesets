rule Trojan_Danger_Trojan_GenericKD_67166905_426_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_426_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96667c6849cdc7f5aa8b0136da703240f2f35809cb0ea650d8ec73eb431be535"

  strings:
    $s1 = "?Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}