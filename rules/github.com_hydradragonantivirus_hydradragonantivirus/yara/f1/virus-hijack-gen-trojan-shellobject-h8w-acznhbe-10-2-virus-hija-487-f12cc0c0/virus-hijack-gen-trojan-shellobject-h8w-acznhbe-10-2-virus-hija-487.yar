rule _Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_10_2_Virus_Hija_487 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e68803ee118256c8a1729b7d1f0b761ccdfd50cff611cfcd9d98f879a15410e"
    hash2       = "0c3087201b875290716203109c116aa67092952b7b0b983ca0414fc95c913c6e"
    hash3       = "c1f695c43e223422681b9db47bacb1180d4b32317eb12214b115efca6b3d3cc7"
    hash4       = "3c0e62668297340d7c921f31ff8b93aef4045fd8451e2ed1af51487b4b840a0b"
    hash5       = "e25748fc0a21f5828cad702244731a582eb13e87950adadf0ac99906d769edb3"
    hash6       = "ec9db3112adce1d4c63aecf111590d20cec1642c9fd8c8c5f975ae0253c6afd1"
    hash7       = "12ee7d854db5ab4ed51117aba115e75b258f54aff30972d7718f7502316d8a0f"

  strings:
    $s1 = "<Package Id=\"OneNoteMUI.it-it\" Type=\"MSI\" Path=\"OneNoteMUI.MSI\" Version=\"1.0\" ProductCode=\"{90120000-00A1-0410-0000-000" ascii
    $s2 = "<Package Id=\"OneNoteMUI.it-it\" Type=\"MSI\" Path=\"OneNoteMUI.MSI\" Version=\"1.0\" ProductCode=\"{90120000-00A1-0410-0000-000" ascii
    $s3 = "<Feature Id=\"OneNoteToIEAddinIntl_1040\" Cost=\"0\">" fullword ascii
    $s4 = "<Feature Id=\"OneNoteMobileDeviceFiles_1040\" Cost=\"443041\">" fullword ascii
    $s5 = "<Feature Id=\"OneNoteFilesIntl_1040\" Cost=\"11758992\">" fullword ascii
    $s6 = "<Feature Id=\"SetupXmlFiles\" Cost=\"3498\">" fullword ascii
    $s7 = "<Feature Id=\"SetupControllerFiles\" Cost=\"3498\">" fullword ascii
    $s8 = "<Feature Id=\"OneNoteHelpFilesIntl_1040\" Cost=\"1051157\">" fullword ascii
    $s9 = "<Feature Id=\"OneNoteNonBootFilesIntl_1040\" Cost=\"25644735\">" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}