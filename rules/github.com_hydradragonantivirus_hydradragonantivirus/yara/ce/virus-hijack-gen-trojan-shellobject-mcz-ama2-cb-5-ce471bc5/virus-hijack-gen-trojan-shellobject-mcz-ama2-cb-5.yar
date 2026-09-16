rule Virus_Hijack_Gen_Trojan_ShellObject_mCZ_ama2_Cb_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.mCZ@ama2@Cb_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40de2f32ab9c2d0752e9e2bb50f816301f59352b1a8432bbe1723226256cf025"

  strings:
    $s1 = "SMB Share For DevelopmentFiles path" fullword wide
    $s2 = "Deleting SMB Share For DevelopmentFiles path" fullword wide
    $s3 = "Developer Tools Service" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}