rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_27_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_27_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97810779958e0d9dae2d35a66f0e5fc046e95dd8b4dfba410b9326738519179a"

  strings:
    $s1  = "*** The MapEditor1 Project *** An XNA Xtreme 101 game by 3d Buzz " fullword wide
    $s2  = "Available Commands:" fullword wide
    $s3  = "NOTE: You may type 'help' at any time to see the a list of commands" fullword wide
    $s4  = "Map Editor 1 -- " fullword wide
    $s5  = "You have entered a red room. There is a locked door to the south" fullword wide
    $s6  = "You have entered a green room. There is a locked door to the north." fullword wide
    $s7  = " has been dropped into this room" fullword wide
    $s8  = "Press a key to begin" fullword wide
    $s9  = "You have picked up a key" fullword wide
    $s10 = "Error serializing map" fullword wide
    $s11 = "Error deserializing map" fullword wide
    $s12 = " in your inventory" fullword wide
    $s13 = "Grid Snap Size:" fullword wide
    $s14 = "Map Size (w,h):" fullword wide
    $s15 = "Input not understood" fullword wide
    $s16 = "move(north south,east,west)" fullword wide
    $s17 = "You may now close the window" fullword wide
    $s18 = "Blue Ball" fullword wide
    $s19 = "Green Ball" fullword wide
    $s20 = "Yellow Ball" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}