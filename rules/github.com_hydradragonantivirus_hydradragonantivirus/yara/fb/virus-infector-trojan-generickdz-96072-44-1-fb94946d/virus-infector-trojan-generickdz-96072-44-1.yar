rule Virus_Infector_Trojan_GenericKDZ_96072_44_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Trojan.GenericKDZ.96072_44_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ec24dc47d35b9330a5ba3260f749bd13dbed3a0db409aa51b563a48107e8162"

  strings:
    $s1 = "derived\" stEvt:parameters=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.ii" ascii
    $s2 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s3 = "derived\" stEvt:parameters=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.ii" ascii
    $s4 = "4899-ca88-7f42-9516-8e7635808df3\" stEvt:when=\"2019-01-07T19:44:27+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windo" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}