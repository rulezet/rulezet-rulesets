rule Virus_Hijack_Gen_Trojan_ShellObject_suZ_aO_SNbk_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.suZ@aO!SNbk_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2e89071378a96eb275ccde54b836dd3b266635bab9463684acfcba62a9771ba"

  strings:
    $s1 = " stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b65" ascii
    $s2 = "torTool=\"Adobe Photoshop CC 2018 (Windows)\" xmp:CreateDate=\"2018-12-02T15:50:06+08:00\" xmp:ModifyDate=\"2019-01-07T19:44:27+" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}