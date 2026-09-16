rule Trojan_Hooker_Gen_Variant_Ransom_Hydracrypt_7 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Gen.Variant.Ransom.Hydracrypt.7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "878e1af72e84ba569e5333eb6d9d925bab2551bb18a905cc6ddcd4a4e0172530"

  strings:
    $s1  = "Respect nodded - www.Anybody.com" fullword wide
    $s2  = "Columbus organized*Create task grade concerned underline poet4Bicycle struggle failed Columbus zero pen eventually,Driven poet c" wide
    $s3  = "Complex author loss" fullword wide
    $s4  = "Swam stove graph fairly)Operation curious silk thee tonight nails" fullword wide
    $s5  = "Author :" fullword wide
    $s6  = "Create arrow research owner\"Nails pictured fewer stared review1Primitive primitive combination accept bean slept" fullword wide
    $s7  = "Offer basis<Bicycle concerned organized owner comfortable route previous Plus elephant active tea blanket#Willing primitive seld" wide
    $s8  = "Betsy hell thrown gain1Powder belt remove hearing Alice author principal" fullword wide
    $s9  = "Grade syllable pan#Affect Johnson author pan pot graph" fullword wide
    $s10 = "Halfway stomach evidence'Trick Columbus steep etc eventually Tim!Tribe Eddy specific pictured hang" fullword wide
    $s11 = "Anybody" fullword wide
    $s12 = "Purple April spider mouse worse Headed previous collect research" fullword wide
    $s13 = "Introduced bush" fullword wide
    $s14 = "Text to Insert" fullword wide
    $s15 = "Home Page :" fullword wide
    $s16 = "Select theme : " fullword wide
    $s17 = "You want to &go to :" fullword wide
    $s18 = "Nails luck fifth fed" fullword wide
    $s19 = "Feature pile military(Gain religious Johnson fastened gasoline'Mighty worry oldest spider trick select" fullword wide
    $s20 = "Planning blanket" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}