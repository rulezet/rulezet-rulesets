rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_66_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_66_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70302728776e8ce531a513dbe48f1f240b93de16a4b059aae51301ea4ad20491"

  strings:
    $s1  = "Monotype - Bodoni MT Poster Compressed" fullword wide
    $s2  = "Monotype - French Script MT Regular" fullword wide
    $s3  = "Monotype - Script MT Bold Regular" fullword wide
    $s4  = "TWindows 95 - Cordia New Bold" fullword wide
    $s5  = "Windows 95 - Cordia New Bold Italic" fullword wide
    $s6  = "Windows 95 - CordiaUPC Bold" fullword wide
    $s7  = "Windows 95 - CordiaUPC Bold Italic" fullword wide
    $s8  = "Monotype - Tw Cen MT Condensed Bold" fullword wide
    $s9  = "Monotype - Tw Cen MT Condensed" fullword wide
    $s10 = "Monotype - Rockwell Condensed" fullword wide
    $s11 = "tMonotype - Gloucester MT Extra Condensed" fullword wide
    $s12 = "Monotype - Gill Sans Ultra Bold Condensed" fullword wide
    $s13 = "Monotype - Gill Sans MT Condensed" fullword wide
    $s14 = "zMonotype - Gill Sans MT Ext Condensed Bold" fullword wide
    $s15 = "{Monotype - Franklin Gothic Medium Cond Regular" fullword wide
    $s16 = "Monotype - Franklin Gothic Demi Cond Regular" fullword wide
    $s17 = "Monotype - Bodoni Condensed" fullword wide
    $s18 = "Monotype - Tw Cen MT Condensed Extra Bold" fullword wide
    $s19 = "Monotype - Rockwell Condensed Bold" fullword wide
    $s20 = " Monotype - DokChampa" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}