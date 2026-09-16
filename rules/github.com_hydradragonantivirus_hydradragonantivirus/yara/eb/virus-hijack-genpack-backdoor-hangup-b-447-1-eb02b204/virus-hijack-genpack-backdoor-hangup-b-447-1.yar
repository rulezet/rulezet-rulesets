rule Virus_Hijack_GenPack_Backdoor_Hangup_B_447_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_447_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "749442ed7152e5224eeecfef756b154a11e2386e5304582c5ecca9bcaa1274cf"

  strings:
    $s1 = "<rdf:li stEvt:action=\"created\" stEvt:instanceID=\"xmp.iid:94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50" ascii
    $s2 = "8:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\"/> <rdf:li stEvt:acti" fullword ascii
    $s3 = "n=\"saved\" stEvt:instanceID=\"xmp.iid:bda3dc4b-caee-fd46-b85f-119c665623ef\" stEvt:when=\"2018-12-02T16:02:59+08:00\" stEvt:sof" ascii
    $s4 = "gent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d9d77" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}