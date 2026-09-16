rule _Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_11_1_Virus_Hija_132 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@aq5b2kh_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_16_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_17_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash2       = "00803b2a9624ab755ca403c3abbf03d7dc3ac396a7c3fbcfb7471d7281cdf9d0"
    hash3       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"
    hash4       = "2b6862758d7e1fa0b613e8ef792cc1c36a85e6c0806094fb9cbe5c36045e1dbf"
    hash5       = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash6       = "9b1f053694c3db989f5c342cf8e2239bee4a1942950b85043637104969e007fe"
    hash7       = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"
    hash8       = "322b1709b0a1998c1bcc8d7ecf62946f9bc72e205ae3f51181890f71efcba474"
    hash9       = "d77b112f1683e3c12780036badc6740837837590150bd82023b8f87eb19ac119"
    hash10      = "b191c91e710f1e6d5bba7192208e4582b57d6ca6ab1478dbb8b815207d74aa5f"
    hash11      = "819bdd89651a57972b9b57227d3b6bd3d94ff991732ba0b0e8459b9fb607a9f4"
    hash12      = "6300694b02f0d03c3a18fe78114e8ee3bb4ccb33360a8beef079c18ca3bc5e8a"
    hash13      = "97bc5369195339aa2c26e05972ac2b0e937dbc52dd3a05bc4f29533ffc3d7dbd"
    hash14      = "7a123956fa172c66ed84236a35e0b1f3587bf3d190c604be3c7399fca5ba4571"

  strings:
    $s1  = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
    $s2  = "<html><head/><body><p>Discover how to <a href=\"https://www.mendeley.com/guides/desktop/04-read-highlight-annotate?dgcid=Mendele" ascii
    $s3  = "<html><head/><body><p>Discover how to <a href=\"https://www.mendeley.com/guides/desktop/04-read-highlight-annotate?dgcid=Mendele" ascii
    $s4  = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
    $s5  = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
    $s6  = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
    $s7  = "<html><head/><body><p><a href=\"https://www.mendeley.com/guides/using-citation-editor?dgcid=Mendeley_Desktop_Onboarding-Help-Cit" ascii
    $s8  = "<html><head/><body><p><a href=\"https://www.mendeley.com/guides/using-citation-editor?dgcid=Mendeley_Desktop_Onboarding-Help-Cit" ascii
    $s9  = "Try Mendeley <a href=\"https://mendeley.com/reference-management/web-importer/#id_1?dgcid=Mendeley_Desktop_Onboarding-Add-Import" ascii
    $s10 = "Please, report to Mendeley at support@mendeley.com including the error status %1." fullword ascii
    $s11 = "layoutHorizontally() - Missing content action" fullword ascii
    $s12 = "You will be directed to login to Zotero to connect to their API." fullword ascii
    $s13 = "f:documentID=\"xmp.did:945FFBAB213A11E0992992A71BAF2C51\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>" fullword ascii
    $s14 = "f#\" xmp:CreatorTool=\"Adobe Photoshop CS5 Macintosh\" xmpMM:InstanceID=\"xmp.iid:945FFBAC213A11E0992992A71BAF2C51\" xmpMM:Docum" ascii
    $s15 = "Click here to <b>import</b> documents and folders to your library or <b>create new</b> entries manually." fullword ascii
    $s16 = "<html><head/><body><p><span style=\" font-size:14pt; color:#2d89db;\">Claim authorship</span></p></body></html>" fullword ascii
    $s17 = "Ref:documentID=\"xmp.did:CCA964442CAC11E28E6AC7C8358705FC\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>" fullword ascii
    $s18 = "Ref:documentID=\"xmp.did:CA862729EF1911E1A069FDDA7011C907\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>q" fullword ascii
    $s19 = "Ref:documentID=\"xmp.did:CCA964402CAC11E28E6AC7C8358705FC\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>" fullword ascii
    $s20 = "The selected file was created by a version of Zotero which is not currently supported (Database version %1)." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}