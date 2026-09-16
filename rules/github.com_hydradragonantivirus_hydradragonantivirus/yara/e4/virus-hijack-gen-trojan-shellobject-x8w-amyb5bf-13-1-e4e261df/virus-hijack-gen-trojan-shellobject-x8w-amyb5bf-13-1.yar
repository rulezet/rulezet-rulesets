rule Virus_Hijack_Gen_Trojan_ShellObject_x8W_amYB5Bf_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.x8W@amYB5Bf_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cfae8e42af1cb1e9dabad8627d1e31cb6e341046b2bb08184d67e4a4239575e"

  strings:
    $s1 = "018-12-02T16:02:59+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}