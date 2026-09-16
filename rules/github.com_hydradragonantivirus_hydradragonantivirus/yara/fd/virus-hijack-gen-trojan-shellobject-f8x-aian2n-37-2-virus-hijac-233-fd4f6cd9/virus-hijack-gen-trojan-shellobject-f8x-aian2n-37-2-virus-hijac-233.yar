import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_37_2_Virus_Hijac_233 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_37_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_38_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e777f5c1eeafd831542de99f4ac16de2e1de9f0c547c4b1c4f411bb3455bd5e"
    hash2       = "91a50464f8803d2538f97f87d2c9b7a0f48330cec585aee25c4e9a44fed27edb"

  strings:
    $s1  = "ListBox Functions 2001 v 2 - By: source                     (c)2001 source                                     visit:www.vbfx.ne" ascii
    $s2  = "by entering a path ie: c:\\windows\\desktop\\ into the textbox located at the bottom of this frame, and pressing save it will sa" ascii
    $s3  = "ListBox Functions 2001 v2 - by source - www.vbfx.net" fullword ascii
    $s4  = "a textbox without using common dialog" fullword ascii
    $s5  = "t                  latest updates: www.planetsourcecode.com" fullword ascii
    $s6  = "load w/ com. dialog" fullword ascii
    $s7  = "save w/ com. dialog" fullword ascii
    $s8  = "Using common dialog it saves two listbox's, the list 3 and list4 to one file" fullword ascii
    $s9  = "Bill - 20" fullword wide
    $s10 = "Jacko - 500" fullword wide
    $s11 = "Mary - 100" fullword wide
    $s12 = "clears the above list of all content" fullword ascii
    $s13 = "clears the above list of all its content" fullword ascii
    $s14 = "text files (*.txt)|*.txt|list files (*.lst)|*.lst|all files (*.*)|*.*" fullword wide
    $s15 = "this will add the contents of the textbox to the left into the listbox 1" fullword ascii
    $s16 = "This clears your clipboard, then copies list1 to your clipboard, by pressing CTRL+V you will paste the contents of list1 anywher" ascii
    $s17 = "by pressing this it add's the contents of text3(left) and text4(right) into list3(left) and list4(right)." fullword ascii
    $s18 = "by entering a path ie: c:\\windows\\desktop\\ into the textbox located at the bottom of this frame, and pressing save it will sa" ascii
    $s19 = "clears all listbox's extremely fast" fullword ascii
    $s20 = "This will clear the contents of list1" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "a414931e6c4797880a9e1e14a735cf39" and (8 of them)
    ) or (all of them)
}