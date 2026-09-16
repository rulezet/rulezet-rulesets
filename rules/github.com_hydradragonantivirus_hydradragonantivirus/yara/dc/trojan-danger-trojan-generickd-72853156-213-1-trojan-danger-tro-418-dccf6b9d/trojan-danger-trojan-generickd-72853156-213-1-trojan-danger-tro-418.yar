import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72853156_213_1_Trojan_Danger_Tro_418 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_213_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_230_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_243_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_251_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_258_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_263_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "921779133cdc43b786442374574e97408407ed2d6fa24d8ea85522f5bce9eddc"
    hash2       = "a9afbee7bbec6653b9967575d8f72ad9f9aae8c2df538927a9af87d1efe11cd3"
    hash3       = "878f678f59a8a2e71be8d75fb03105b976a8035f9fa5f59068e2646bdb90ab0a"
    hash4       = "291cae56d5ea928f97a428957b02145406abcada610a89b09428a4e5e8a15a5f"
    hash5       = "6c2e5413d580488fa890d4b6e423683b0a82a32c0d8cb5d88a466c62f75b4a17"
    hash6       = "6d7e4cd87f8ce518cf33753b2689d8b1f4a0014c717ed1ec249b5113cd3d8fa1"

  strings:
    $s1  = "to be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of thisamq" ascii
    $s2  = "qvaqqdSysconfirm the license is associated with the licensed computer. This process is called " fullword ascii
    $s3  = "g a 1 Year Oracle Hosted Term shall commence on the effective" fullword ascii
    $s4  = "sqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaq1 Year Oracle Hosted Term: A program license specifyin" ascii
    $s5  = "services.qamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqa" ascii
    $s6  = "sqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaq1 Year Oracle Hosted Term: A program license specifyin" ascii
    $s7  = "above will not be applied to such taxes, materials and/or expenses. Learning credits are valid for a period of 12 months fromSys" ascii
    $s8  = "ysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqactivation. If you have not entered a product key during the time permitted for act" ascii
    $s9  = "ysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqorders during any 12 month period." fullword ascii
    $s10 = "ysqamqqvaqPerson: is defined as your employee or contractor who is actively working on behalf of your organization or a former" fullword ascii
    $s11 = "confidential legends or markings placed upon the TRMs. Oracle shall retain all title, copyright and other proprietary rights inS" ascii
    $s12 = "ivation, most" fullword ascii
    $s13 = "above will not be applied to such taxes, materials and/or expenses. Learning credits are valid for a period of 12 months fromSys" ascii
    $s14 = "qqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamonly to reinstall the software on the lic" ascii
    $s15 = "confidential legends or markings placed upon the TRMs. Oracle shall retain all title, copyright and other proprietary rights inS" ascii
    $s16 = "qamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdS" ascii
    $s17 = "Microsoft products. You agree that we may use and disclose the information as described in our PrivacymqqvaqqdSysqamqqvaqqdSysqe" ascii
    $s18 = " an employee of an organization that has a Microsoft Volume License agreement with SoftwareamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSy" ascii
    $s19 = "to be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of thisamq" ascii
    $s20 = "as the licensing rules which are listed below.qqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdS" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "149c68dc98a2f671a10697b9eaa5faa4" and (8 of them)
    ) or (all of them)
}