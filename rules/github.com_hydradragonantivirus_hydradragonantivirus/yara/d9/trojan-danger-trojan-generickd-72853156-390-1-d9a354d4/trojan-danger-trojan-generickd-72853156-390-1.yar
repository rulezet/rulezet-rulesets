rule Trojan_Danger_Trojan_GenericKD_72853156_390_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_390_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec8c3a952c6e4197809f0b45a3c4f2240519535f204cdaaa5d158e093112b349"

  strings:
    $s1 = "availability of ExtenSysqemofnueSysqemelkmtSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamq" ascii
    $s2 = "availability of ExtenSysqemofnueSysqemelkmtSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamq" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}