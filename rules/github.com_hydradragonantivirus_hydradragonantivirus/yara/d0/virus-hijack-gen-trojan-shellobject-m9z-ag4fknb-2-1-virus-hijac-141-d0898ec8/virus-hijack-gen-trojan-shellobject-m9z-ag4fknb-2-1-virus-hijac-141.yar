import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_m9Z_aG4fkNb_2_1_Virus_Hijac_141 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.m9Z@aG4fkNb_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.m9Z@aG4fkNb_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.m9Z@aG4fkNb_4_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.m9Z@aG4fkNb_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_14_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_16_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.MuZ@amBwvTb_17_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_18_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e64820535c92a18e30b0f8b26aa0f3e53f569e659b2d9d42b5836943910b21c"
    hash2       = "817e67fc69a8a0b2ca218dc11876f7884d8fb2655df58145af10b36f7d6f509e"
    hash3       = "51e020a169105760ac88716ecbac58a1419c233b4bb00b7bb72ef187b261a074"
    hash4       = "1c9c2dd1de3fe7494f002d9360fc3c672127f018c370230fec12438a3eceb0c3"
    hash5       = "5a5db7f86f8a28de1c782f86f8e2ea684abfa658b91e175de437d4e6755ae8bd"
    hash6       = "aa6af1b199ca7767ff52adfe357f5982abc8b7c7070ee1595d5a327facd1c90b"
    hash7       = "a3376a718005e68c993f282b7fc1b034f002093c464189ee1b7319338ed01ff8"
    hash8       = "679c24a33144a5ed19f38a5912abc821d088873c854ffb961a28a5b744c22121"
    hash9       = "1c0e03798f8a405b63713c1dc838085c0ee30f15b9aeb75dacd1740544ee0834"
    hash10      = "845e26db170f34989574caecec665fca9281202192426071e076d8e2deb81175"

  strings:
    $s1  = "String view0Show a hexadecimal dump of the document" fullword wide
    $s2  = "ex19c Version 1.0" fullword wide
    $s3  = "of that september afternoon" fullword ascii
    $s4  = "is where I first" fullword ascii
    $s5  = "St&ring View" fullword wide
    $s6  = "About ex19c" fullword wide
    $s7  = "Copyright (C) 1997" fullword wide
    $s8  = "Ex19c Document" fullword wide
    $s9  = "%Show the document as text" fullword wide
    $s10 = "                     the licorice sticks" fullword ascii
    $s11 = "                  fell in love" fullword ascii
    $s12 = "                      with unreality" fullword ascii
    $s13 = "&Hex View" fullword wide
    $s14 = "Hew view" fullword wide
    $s15 = "The pennycandystore beyond the El" fullword ascii
    $s16 = "A cat upon the counter moved among" fullword ascii
    $s17 = "ex19c MFC Application" fullword wide
    $s18 = "ex19c Application" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "6084ff3a75cf24854dbb3116ce3ff740" and (8 of them)
    ) or (all of them)
}