rule Virus_Infector_Trojan_GenericKDZ_96072_28_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Trojan.GenericKDZ.96072_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2290fb150de6df6c4ee7d23d3d8186bcc73404166a77630ec0ad846475eda4b8"

  strings:
    $s1 = "7e-5800-2842-91eb-924792347dc3\" stRef:originalDocumentID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> " ascii
    $s2 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s3 = "g to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" stEvt:when=" ascii
    $s4 = "-01-07T19:44:27+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:Histo" ascii
    $s5 = "xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee3" ascii
    $s6 = "png to image/jpeg\"/> <rdf:li stEvt:action=\"derived\" stEvt:parameters=\"converted from image/p" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}