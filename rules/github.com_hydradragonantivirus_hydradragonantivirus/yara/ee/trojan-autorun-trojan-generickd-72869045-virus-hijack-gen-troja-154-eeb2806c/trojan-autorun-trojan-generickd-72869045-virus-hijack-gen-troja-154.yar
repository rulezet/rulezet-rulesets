rule _Trojan_Autorun_Trojan_GenericKD_72869045_Virus_Hijack_Gen_Troja_154 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.72869045.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@aq5b2kh_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_16_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_17_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b4d08c1939546a758d6fe9b1b5284dc628aff3fef3cb798a4e535143a008a56"
    hash2       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash3       = "00803b2a9624ab755ca403c3abbf03d7dc3ac396a7c3fbcfb7471d7281cdf9d0"
    hash4       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"
    hash5       = "2b6862758d7e1fa0b613e8ef792cc1c36a85e6c0806094fb9cbe5c36045e1dbf"
    hash6       = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash7       = "9b1f053694c3db989f5c342cf8e2239bee4a1942950b85043637104969e007fe"
    hash8       = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"
    hash9       = "322b1709b0a1998c1bcc8d7ecf62946f9bc72e205ae3f51181890f71efcba474"
    hash10      = "d77b112f1683e3c12780036badc6740837837590150bd82023b8f87eb19ac119"
    hash11      = "b191c91e710f1e6d5bba7192208e4582b57d6ca6ab1478dbb8b815207d74aa5f"
    hash12      = "819bdd89651a57972b9b57227d3b6bd3d94ff991732ba0b0e8459b9fb607a9f4"
    hash13      = "6300694b02f0d03c3a18fe78114e8ee3bb4ccb33360a8beef079c18ca3bc5e8a"
    hash14      = "97bc5369195339aa2c26e05972ac2b0e937dbc52dd3a05bc4f29533ffc3d7dbd"
    hash15      = "7a123956fa172c66ed84236a35e0b1f3587bf3d190c604be3c7399fca5ba4571"

  strings:
    $s1  = "Matching documents to catalog - %1 remaining" fullword ascii
    $s2  = "author:\"%1\"" fullword ascii
    $s3  = "Password (if required):" fullword ascii
    $s4  = "1dialogImportResult(QList<QFileInfo>,bool)" fullword ascii
    $s5  = "Mendeley is using your system connection settings" fullword ascii
    $s6  = "Download Style Url" fullword ascii
    $s7  = "Use system connection settings" fullword ascii
    $s8  = "Download Style:" fullword ascii
    $s9  = "<html><head/><body><p><span style=\" font-size:12pt;\">Use the </span><span style=\" font-size:12pt; font-weight:600;\">highligh" ascii
    $s10 = "<html><head/><body><p><span style=\" font-size:12pt;\">Use the </span><span style=\" font-size:12pt; font-weight:600;\">highligh" ascii
    $s11 = "publication:\"%1\"" fullword ascii
    $s12 = "Drag some widgets to update the example" fullword ascii
    $s13 = "/* This style can be overriden by any css that is embedded into the text in this label */" fullword ascii
    $s14 = "throbber" fullword wide
    $s15 = "Miss Author" fullword ascii
    $s16 = "PRIVATE ANNOTATIONS" fullword ascii
    $s17 = "SOCKS 5 Proxy" fullword ascii
    $s18 = "Please try again or contact <a href='%1'>support</a> if the problem continues." fullword ascii
    $s19 = "There was an error fetching related documents, please try again." fullword ascii
    $s20 = "Deleted User" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}