rule _Trojan_Autorun_Trojan_GenericKD_72869045_Virus_Hijack_Gen_Troja_321 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.72869045.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@aq5b2kh_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_16_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_17_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_18_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b4d08c1939546a758d6fe9b1b5284dc628aff3fef3cb798a4e535143a008a56"
    hash2       = "9dd481aae9a5d9bb4492b165f159bb9b6e7d7a9fc94fa24820790c8c1d87ee10"
    hash3       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash4       = "00803b2a9624ab755ca403c3abbf03d7dc3ac396a7c3fbcfb7471d7281cdf9d0"
    hash5       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"
    hash6       = "2b6862758d7e1fa0b613e8ef792cc1c36a85e6c0806094fb9cbe5c36045e1dbf"
    hash7       = "9b1f053694c3db989f5c342cf8e2239bee4a1942950b85043637104969e007fe"
    hash8       = "322b1709b0a1998c1bcc8d7ecf62946f9bc72e205ae3f51181890f71efcba474"
    hash9       = "d77b112f1683e3c12780036badc6740837837590150bd82023b8f87eb19ac119"
    hash10      = "b191c91e710f1e6d5bba7192208e4582b57d6ca6ab1478dbb8b815207d74aa5f"
    hash11      = "819bdd89651a57972b9b57227d3b6bd3d94ff991732ba0b0e8459b9fb607a9f4"
    hash12      = "6300694b02f0d03c3a18fe78114e8ee3bb4ccb33360a8beef079c18ca3bc5e8a"
    hash13      = "97bc5369195339aa2c26e05972ac2b0e937dbc52dd3a05bc4f29533ffc3d7dbd"
    hash14      = "7a123956fa172c66ed84236a35e0b1f3587bf3d190c604be3c7399fca5ba4571"
    hash15      = "6eca375518c871cbafa55bb8b3f323c5138a90fe23a2590be889548e4186ae0c"
    hash16      = "66d0faa4052007cff3969e3b850cf218a17f7cc2a1282c9c956e0402fcfc35e6"
    hash17      = "1300abe8989a2b3b5e1ab0102c4decd1bb1035a73bacbe2b00a064fb74207f7b"

  strings:
    $s1 = "Failure authenticating PsExec service on %s." fullword wide
    $s2 = "Usage: psexec [\\\\computer[,computer2[,...] | @file]][-u user [-p psswd]][-n s][-r servicename][-h][-l][-s|-e][-x][-i [session]" ascii
    $s3 = "Usage: psexec [\\\\computer[,computer2[,...] | @file]][-u user [-p psswd]][-n s][-r servicename][-h][-l][-s|-e][-x][-i [session]" ascii
    $s4 = "PsExec requires Windows XP or higher." fullword ascii
    $s5 = "Error creating key file on %s:" fullword wide
    $s6 = "Error writing key file on %s:" fullword wide
    $s7 = "-c [-f|-v]][-w directory][-d][-<priority>][-a n,n,...] cmd [arguments]" fullword ascii
    $s8 = "Copying authentication key to %s..." fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}