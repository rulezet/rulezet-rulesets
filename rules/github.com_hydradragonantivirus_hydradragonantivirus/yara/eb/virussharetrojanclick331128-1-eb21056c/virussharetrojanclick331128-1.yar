rule VirusShareTrojanClick331128_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanClick331128_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b404fb3d9c89fdd5a31a1407a6fb08976fd3b1b451d4968de8c4c930645f988"

  strings:
    $s1  = "E:\\mtasa-blue-master (2)\\mtasa-blue-master\\Bin\\Multi Theft Auto.pdb" fullword ascii
    $s2  = "Multi Theft Auto.exe" fullword ascii
    $s3  = "            <GameExecutable path=\"Multi Theft Auto.exe\" />" fullword wide
    $s4  = "            <Developer URI=\"http://mtasa.com\">MTA Team</Developer>" fullword wide
    $s5  = "(C) 2003 - 2014 Multi Theft Auto" fullword wide
    $s6  = "Failed to load: '%s'" fullword ascii
    $s7  = "Error %u: %s" fullword ascii
    $s8  = "This version of MTA requires Windows XP SP3 or later" fullword ascii
    $s9  = "(If the page fails to load, paste (CTRL-V) the URL into your web browser)" fullword ascii
    $s10 = "LoadLibrary '%s' succeeded on change to directory '%s'" fullword ascii
    $s11 = "                        <FileTask path=\"Multi Theft Auto.exe\" arguments=\"\" />" fullword wide
    $s12 = "        <Description>Play San Andreas with an all new Multiplayer twist!  Multi Theft Auto is an open-source game engine that ad" wide
    $s13 = "Do you want to see some on-line help about this problem ?" fullword ascii
    $s14 = "[Invalid parameter] " fullword ascii
    $s15 = "[Format exception] " fullword ascii
    $s16 = "Trouble %s" fullword ascii
    $s17 = "Your browser will now display a web page with some help infomation." fullword ascii
    $s18 = "Software\\Multi Theft Auto: San Andreas All" fullword ascii
    $s19 = "Multi Theft Auto" fullword wide
    $s20 = "Multi Theft Auto Launcher" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}