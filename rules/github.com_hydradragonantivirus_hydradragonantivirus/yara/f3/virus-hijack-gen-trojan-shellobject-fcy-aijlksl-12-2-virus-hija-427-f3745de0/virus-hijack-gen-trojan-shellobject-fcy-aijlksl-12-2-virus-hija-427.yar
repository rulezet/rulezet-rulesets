rule _Virus_Hijack_Gen_Trojan_ShellObject_fCY_aijlKSl_12_2_Virus_Hija_427 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Y@aivto4c_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adfd442678401b34be588f10eeb2be0c1e01234f86542cbc2002dccf1fd8fb45"
    hash2       = "537245cb51ba8f92569109abea9da013bc2c389b997545df6127480cc799f571"

  strings:
    $s1  = "OneNote Legacy Log" fullword wide
    $s2  = "OneNote Boot Dialogs" fullword wide
    $s3  = "OneNote First Run" fullword wide
    $s4  = "Font Picker Data Manager" fullword wide
    $s5  = "OneNote Optimization" fullword wide
    $s6  = "OneNote Backup" fullword wide
    $s7  = "OneNote Print" fullword wide
    $s8  = "OneNote Presence" fullword wide
    $s9  = "OneNote Launch ScreenClip" fullword wide
    $s10 = "OneNote Launch via Arguments" fullword wide
    $s11 = "OneNote Image" fullword wide
    $s12 = "OneNote Navigation" fullword wide
    $s13 = "OneNote Notebook Manager" fullword wide
    $s14 = "OneNote Click Note" fullword wide
    $s15 = "OneNote Quick Notes" fullword wide
    $s16 = "OneNote Audio" fullword wide
    $s17 = "OneNote Note Tag" fullword wide
    $s18 = "OneNote Math" fullword wide
    $s19 = "OneNote Text" fullword wide
    $s20 = "OneNote Page Analysis" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}