import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72853156_220_1_Trojan_Danger_Tro_437 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_220_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_236_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_290_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_383_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "470eeb4982f094384023e38e7d9eb75a4aa06b67f58d991ff484e4b49d10fc6a"
    hash2       = "5fb34591ef0c0cef96a0689afc7bbb12ca3c2f9dd23d6aaa3a57dd17cfec0248"
    hash3       = "fc45952f1d1061afd5b9d3c401e6703a9abeb6a340d8862a8ce41dbe4734c83f"
    hash4       = "53c409169a11bd969e871b3a2591b2af2847f76e1d0468f4e7d42f460e5078f6"

  strings:
    $s1  = "Implementation Services, Packaged Methods, Architecture Services, Accelerator Services, Assessment Services andqqdSysqamqqvaqqdS" ascii
    $s2  = "proofing tool that offers additional language version support for the software, you may use the additionalSysqamqqvaqqdSysqamqqv" ascii
    $s3  = "proofing tool that offers additional language version support for the software, you may use the additionalSysqamqqvaqqdSysqamqqv" ascii
    $s4  = "ysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvathen Cost of Goods Sold shall be equal to 75% of total company reve" ascii
    $s5  = "Implementation Services, Packaged Methods, Architecture Services, Accelerator Services, Assessment Services andqqdSysqamqqvaqqdS" ascii
    $s6  = "infringement claim could have been avoided by using an unaltered current version of the Material which was provided to theSysqam" ascii
    $s7  = "infringement claim could have been avoided by using an unaltered current version of the Material which was provided to theSysqam" ascii
    $s8  = "mqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSys" ascii
    $s9  = "qvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqa" ascii
    $s10 = "unless you acquire additional Order Line licenses from Oracle.ysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqemybprfSysq" ascii
    $s11 = "unless you acquire additional Order Line licenses from Oracle.ysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqemybprfSysq" ascii
    $s12 = "qaLabor, a person is defined as an employee or contractor whose time or labor (piece work) or absences are managed by the" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "806f3d2fcfacf778b205188e7e0343bf" and (8 of them)
    ) or (all of them)
}