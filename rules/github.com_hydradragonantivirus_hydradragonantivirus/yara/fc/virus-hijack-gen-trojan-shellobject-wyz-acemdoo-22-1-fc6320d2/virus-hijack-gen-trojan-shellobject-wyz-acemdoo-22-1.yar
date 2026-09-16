rule Virus_Hijack_Gen_Trojan_ShellObject_WyZ_aCEmdoo_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.WyZ@aCEmdoo_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dab13e77b652deb4a11a7b4e5bd6c9745739f84c13f399aea640af6cd342234c"

  strings:
    $s1 = "018-12-02T16:02:59+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}