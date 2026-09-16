rule Trojan_Hooker_Win32_Floxif_A_23 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "386d3e9e0ec770fcfc8e7fdf457431d2f9da3c045674e4bab8794e39a8ca4d78"

  strings:
    $s1 = "level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsof" ascii
    $s2 = "A build of the Launcher for EZ CD Audio Converter Portable, allowing it to be run from a removable drive." fullword wide
    $s3 = "Copyright 1998 - 2019 Jukka Poikolainen & Poikosoft" fullword wide
    $s4 = "EZ CD Audio Converter Portable Launcher" fullword wide
    $s5 = "PortableApp Launcher" fullword wide
    $s6 = ":compatibility.v1\"><application><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supportedOS Id=\"{e2011457-1546-43" ascii
    $s7 = "EZ CD Audio Converter" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}