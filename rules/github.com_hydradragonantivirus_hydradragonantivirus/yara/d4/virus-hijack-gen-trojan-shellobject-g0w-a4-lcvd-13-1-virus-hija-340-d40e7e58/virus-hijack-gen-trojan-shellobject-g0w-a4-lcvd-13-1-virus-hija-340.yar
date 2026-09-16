import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_g0W_a4_lcVd_13_1_Virus_Hija_340 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@aq5b2kh_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_16_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_17_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b1f053694c3db989f5c342cf8e2239bee4a1942950b85043637104969e007fe"
    hash2       = "322b1709b0a1998c1bcc8d7ecf62946f9bc72e205ae3f51181890f71efcba474"
    hash3       = "d77b112f1683e3c12780036badc6740837837590150bd82023b8f87eb19ac119"
    hash4       = "b191c91e710f1e6d5bba7192208e4582b57d6ca6ab1478dbb8b815207d74aa5f"
    hash5       = "819bdd89651a57972b9b57227d3b6bd3d94ff991732ba0b0e8459b9fb607a9f4"
    hash6       = "6300694b02f0d03c3a18fe78114e8ee3bb4ccb33360a8beef079c18ca3bc5e8a"
    hash7       = "97bc5369195339aa2c26e05972ac2b0e937dbc52dd3a05bc4f29533ffc3d7dbd"
    hash8       = "7a123956fa172c66ed84236a35e0b1f3587bf3d190c604be3c7399fca5ba4571"

  strings:
    $s1  = "The software is subject to United States export laws and regulations.You must comply with all domestic and international export " wide
    $s2  = "* anything related to the software, services, content(including code) on third party Intern" fullword wide
    $s3  = " - Service n" fullword wide
    $s4  = " un usage part" fullword wide
    $s5  = "Scanning p" fullword wide
    $s6  = "Initiates an asynchronous add operation t" fullword wide
    $s7  = " un usage particulier et d'absence de co" fullword wide
    $s8  = "regex_error(error_range): The expression contained an invalid ch" fullword ascii
    $s9  = "This agreement describes certain legal rights.You may have other rights under the laws of your country.You may also have righ" fullword wide
    $s10 = "\\'b7\\tab make more copies of the software than specified" fullword ascii
    $s11 = "\\fs20 11.\\tab\\fs19 Disclaimer of Warranty.\\caps0    \\caps The software is licensed \"as - is.\"  You bear the risk of using" ascii
    $s12 = " Washington state law governs the interpretation of this agreement and applies to claim" fullword ascii
    $s13 = "YSINTERNALS gives no express warranties, guarantees or conditions.  You may have additional consu" fullword ascii
    $s14 = "\\fs20 11.\\tab\\fs19 Disclaimer of Warranty.\\caps0    \\caps The software is licensed \"as - is.\"  You bear the risk of using" ascii
    $s15 = "United States.If you acquired the software in the United States, Washington state law governs the interpretation of this agreeme" wide
    $s16 = "Registering Proper" fullword wide
    $s17 = "This is the fir" fullword wide
    $s18 = "The software is subject" fullword wide
    $s19 = "Outside the United States.If you acquired the software in any other country, the laws of th" fullword wide
    $s20 = "It also applies even if Sysinternals knew o" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f1a539a5b71ad53ac586f053145f08ec" and (8 of them)
    ) or (all of them)
}