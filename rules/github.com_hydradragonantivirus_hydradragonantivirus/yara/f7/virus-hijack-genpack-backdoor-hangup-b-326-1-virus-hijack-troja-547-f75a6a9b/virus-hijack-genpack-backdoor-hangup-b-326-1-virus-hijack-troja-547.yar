rule _Virus_Hijack_GenPack_Backdoor_Hangup_B_326_1_Virus_Hijack_Troja_547 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_GenPack.Backdoor.Hangup.B_326_1.vir, Virus.Hijack_Trojan.Agent.DQQO_115_1.vir, Virus.Hijack_Trojan.Agent.GCHT_2_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_169_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_30_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_310_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_550_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_631_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_699_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7c04c91467e40df48f62a79f19f7ae88b08aad0024ae2ad690f19e307c30183"
    hash2       = "013e1561af5bf9d586fa2221f96bc17eb89e60b74310d86bb6e3c3de8419d81f"
    hash3       = "7c8542255d45fc31ba6230288d739ea7ad2334fba1c328316179a24f41ae0fed"
    hash4       = "7add71c99c6b16705746d9789cd7248fa8f8060ef16b7ba0d3ec167468bf5336"
    hash5       = "595f2207a29f763330ce494f27f5cf6e0023fef9140d8677aaae50d49d4b6d59"
    hash6       = "28d7e732c2efd8e9961e219fc6728a7f623ac564263a3ab324f1e29ecf2a9e60"
    hash7       = "57719209fd3ef1aa449f59b5ed842aa170331f99d6c3fc367529c4d6d7c949ae"
    hash8       = "b7625d84cb3d35b06ba2d1c0d52fda13003b1cf26644a17343b675a3d513ded3"
    hash9       = "c7d34faaee030c66183f665d90b92cdbfdfde6e6739dee016b46ac709c964fe8"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)' stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from " ascii
    $s2 = "iid:d5974899-ca88-7f42-9516-8e7635808df3\" stEvt:when=\"2019-01-07T19:44:27+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 201" ascii
    $s3 = "indows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b7" ascii
    $s4 = "14b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792347dc3\" stRef:originalDocumentID=\"xmp.did:" ascii
    $s5 = "iid:d5974899-ca88-7f42-9516-8e7635808df3\" stEvt:when=\"2019-01-07T19:44:27+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 201" ascii
    $s6 = "7eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                                 " ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}