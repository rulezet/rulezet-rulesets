rule _Trojan_Autorun_Trojan_GenericKD_72869045_Virus_Hijack_Gen_Troja_401 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.72869045.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b4d08c1939546a758d6fe9b1b5284dc628aff3fef3cb798a4e535143a008a56"
    hash2       = "9dd481aae9a5d9bb4492b165f159bb9b6e7d7a9fc94fa24820790c8c1d87ee10"
    hash3       = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash4       = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"
    hash5       = "88161fa41e18f1d57a2848956c024bd4376d03ece61626be61b46da1c9cd0062"
    hash6       = "4a358cd38d34db61937690de1c080533535f35e44b7ccc50d5b07c5bc183a797"

  strings:
    $s1  = "This application requires .NET Framework 4.5 or above. Clicking the Install button will download the latest version of this oper" wide
    $s2  = "ERROR: could not create target directory (SquirrelTemp)" fullword ascii
    $s3  = "could not get the Setup version - skipping installation" fullword ascii
    $s4  = "could not get the full path of the Setup file - skipping installation" fullword ascii
    $s5  = "the version of the Setup file is invalid - skipping installation" fullword ascii
    $s6  = "A reboot is required following .NET installation - reboot then run installer again." fullword ascii
    $s7  = "To finish installing the .NET Framework 4.5, the system now needs to restart.  The installation will finish after you restart an" wide
    $s8  = "ERROR: could not create target directory (fallback mode)" fullword ascii
    $s9  = "Downloading the .NET Framework installer" fullword wide
    $s10 = "Unable to write to %s - IT policies may be restricting access to this folder" fullword wide
    $s11 = "The app version already installed is not older than the setup version, skipping installation" fullword ascii
    $s12 = "This application requires the .NET Framework 4.5. Click the Install button to get started." fullword wide
    $s13 = "\"%s\" --install . %s %s" fullword wide
    $s14 = "There was an error while installing the application. Check the setup log for more information and contact the author." fullword wide
    $s15 = "entered MsiOverride mode" fullword ascii
    $s16 = "Open Setup Log" fullword wide
    $s17 = "ERROR: failed to extract installer" fullword ascii
    $s18 = "Setup version is " fullword ascii
    $s19 = "App version is " fullword ascii
    $s20 = "Install .NET 4.5" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}