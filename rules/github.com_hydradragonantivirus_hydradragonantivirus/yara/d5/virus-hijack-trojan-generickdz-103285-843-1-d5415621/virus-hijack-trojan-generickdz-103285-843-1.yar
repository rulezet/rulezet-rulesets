rule Virus_Hijack_Trojan_GenericKDZ_103285_843_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_843_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b99bda00d333317edab73b94182b0403742bbcf4fd4a5abcc79d2de626c84ec"

  strings:
    $s1 = "35808df3\" stEvt:when=\"2019-01-07T19:44:27+08:00\" stEvt:softwareAgent=\"Adobe Pho" fullword ascii
    $s2 = "ID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                " ascii
    $s3 = "s=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9516" ascii
    $s4 = "oshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d774" ascii
    $s5 = "oshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d774" ascii
    $s6 = "124-ed42-8b71-4014b651f934\" stRef:documentID=\"adobe:dEcid:photoshop:ee396c7e-5800-2842-91eb-924792347dc3\" stRef:originalDocum" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}