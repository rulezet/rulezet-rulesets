rule Virus_Hijack_Gen_Trojan_ShellObject_AuZ_aGCmnff_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.AuZ@aGCmnff_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffce54e61365603698482382898ea70bd9802d03cab590812257ed18e51ba5ed"

  strings:
    $s1 = "XAMPP Control Panel" fullword wide
    $s2 = "XAMPP Control Panel for Windows" fullword wide
    $s3 = "Form$.=" fullword ascii
    $s4 = "WEB Site" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}