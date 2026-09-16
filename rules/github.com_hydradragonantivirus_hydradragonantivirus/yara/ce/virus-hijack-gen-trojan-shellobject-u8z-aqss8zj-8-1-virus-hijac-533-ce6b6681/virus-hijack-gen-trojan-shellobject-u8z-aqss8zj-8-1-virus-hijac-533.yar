rule _Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aqsS8zj_8_1_Virus_Hijac_533 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqsS8zj_8_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.v8Z@aqDKVYh_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.wSZ@a8YIsUn_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.z8W@aK0I3Zf_11_1.vir, Virus.Hijack_Gen.Variant.Zusy.540547_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a87312fea0db37e4af5155b3fdbabc16b66ec1fd87be3fe0c0d3ac479b6f074"
    hash2       = "c669cb81ab79f33e1d8e3705e8da07a2e87b20a6232af146aebdd32d0e3f7fca"
    hash3       = "1a288e09abe4d7f368618a9b05bfeea242c595df19993d8b55b502edd027f315"
    hash4       = "b275ea1ff1f1d07a0720482cc94b3e34040a5f1c72b888559c9ec254554425f0"
    hash5       = "d1bbd3bad65c592a23412bf1e66c7f92ef466ab5c30d6fd60bd3418487bb1fb6"

  strings:
    $s1 = "df3\" stEvt:when=\"2019-01-0^T19:44:27+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <" ascii
    $s2 = "nverted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e763" ascii
    $s3 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s4 = "q> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentID=\"adob" ascii
    $s5 = "/rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                                       " ascii
    $s6 = "nverted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e763" ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}