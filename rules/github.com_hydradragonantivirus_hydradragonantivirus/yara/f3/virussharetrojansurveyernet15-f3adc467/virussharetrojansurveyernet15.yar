rule VirusShareTrojanSurveyerNET15 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSurveyerNET15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69e14818260fb68ab7bd50cfaae9094038b7ed4da62a937dae998effe885bd5e"

  strings:
    $s1  = "Downloading Process:" fullword wide
    $s2  = "MotoGP 21 InstallShield Wizard v.1.2.exe" fullword ascii
    $s3  = "Vent, indtil InstallShield Wizard downloader og installerer spillet." fullword wide
    $s4  = "This Wizard will guide you through the installation process of " fullword wide
    $s5  = "2. Enter valid license key to end installation process." fullword wide
    $s6  = " de licence valide pour terminer le processus d'installation." fullword wide
    $s7  = "This Wizard will guide you through the installation process of Rise of the Tomb Raider" fullword wide
    $s8  = "Installing Process:" fullword wide
    $s9  = "2. Activate the license key to end installation process" fullword wide
    $s10 = "Installera Process:" fullword wide
    $s11 = "1. Enter your license key or click 'Get License Key' to obtain one." fullword wide
    $s12 = "marrer l'installation, il est recommand" fullword wide
    $s13 = "1. Enter you license key or click \"Get License Key\" to obtain one" fullword wide
    $s14 = "Wait until InstallShield Wizard will download and install the game." fullword wide
    $s15 = "To activate the game and complete installation setup you need to have a valid License key." fullword wide
    $s16 = "Setup is not complete. If you exit now, the program will not be installed. You may run Setup again at another time to complete t" wide
    $s17 = "dvendige systemfiler uden at skulle genstarte din computer." fullword wide
    $s18 = "Wait untill InstallShield Wizard will download and install the game" fullword wide
    $s19 = "Game files successfully downloaded!" fullword wide
    $s20 = "Setup is not complete. If you exit now, the program will not be installed. Yoy may run Setup again at another time to complete t" wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}