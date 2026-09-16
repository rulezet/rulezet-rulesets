rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aKTibuk_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aKTibuk_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21f8d7ea653f0cc893c9502ca18ea7056621359fc9f97f08a9a916d390a8f79e"

  strings:
    $s1 = "om/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEven" ascii
    $s2 = "xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Photoshop CC 2018 (Windows)\" xmp:CreateD" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}