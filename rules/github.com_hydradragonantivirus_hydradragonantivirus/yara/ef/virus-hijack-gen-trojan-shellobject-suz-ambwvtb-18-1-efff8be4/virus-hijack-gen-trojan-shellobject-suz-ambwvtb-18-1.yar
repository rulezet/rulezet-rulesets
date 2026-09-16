rule Virus_Hijack_Gen_Trojan_ShellObject_suZ_amBwvTb_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.suZ@amBwvTb_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "638fb40b3c438a716a0a138055af919f1998b3ddc68b96d48653dbfc46efbb68"

  strings:
    $s1 = "om/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEven" ascii
    $s2 = "xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Photoshop CC 2018 (Windows)\" xmp:CreateD" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}