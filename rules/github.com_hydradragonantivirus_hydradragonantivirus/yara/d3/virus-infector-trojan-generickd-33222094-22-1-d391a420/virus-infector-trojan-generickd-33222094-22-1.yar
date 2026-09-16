rule Virus_Infector_Trojan_GenericKD_33222094_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Trojan.GenericKD.33222094_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b3533524fee52df34b8d61e6badd7959f3adab1ba3620c079fa9f16f48b55c6"

  strings:
    $s1 = "derived\" stEvt:parameters=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.ii" ascii
    $s2 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s3 = "derived\" stEvt:parameters=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.ii" ascii
    $s4 = "4899-ca88-7f42-9516-8e7635808df3\" stEvt:when=\"2019-01-07T19:44:27+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windo" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}