rule Virus_Hijack_Gen_Trojan_ShellObject_s8Z_aiJFfJo_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aiJFfJo_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f03240f5b1b3c3c76023d4477255c2f6cd44a5a303b3f4491280038ebf783bb6"

  strings:
    $s1 = "om/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEven" ascii
    $s2 = "xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Photoshop CC 2018 (Windows)\" xmp:CreateD" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}