import "pe"
rule _Virus_Hijack_Trojan_Agent_DQQO_396_1_Virus_Hijack_Trojan_Generi_528 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.Agent.DQQO_396_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_358_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de40857f388c3c7ad65ad313c2fe691341c7d1325bec3826bc81c07d0129c729"
    hash2       = "4ba3d0a69094313da376c2b6a3be4539a43ffe3a7696fbcd36d63f6bfe4dd3b0"

  strings:
    $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
    $s2 = "p CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from image/png to image/jpeg\"" ascii
    $s3 = "wareAgent=\"Adobe Photosh" fullword ascii
    $s4 = "pe/ResourceRef#\" xmp:CreatorTool=\"Adobe Photoshop CC 2018 (Windows)\" xmp:CreateDate=\"2018-12-02T15:50:06+08:00\" xmp:ModifyD" ascii
    $s5 = "p CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from image/png to image/jpeg\"" ascii
    $s6 = "pe/ResourceRef#\" xmp:CreatorTool=\"Adobe Photoshop CC 2018 (Windows)\" xmp:CreateDate=\"2018-12-02T15:50:06+08:00\" xmp:ModifyD" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "4aeb6721b008739916fb7a9bdda2ac2e" and (all of them)
    ) or (all of them)
}