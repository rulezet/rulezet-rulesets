rule Trojan_Hooker_Win32_Floxif_A_40 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_40.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ae57c5960e87277c40bb035d8f1aa5156317b908c8d5322652c426383c46856"

  strings:
    $s1 = "Boot Loader Generator v1.5.exe" fullword ascii
    $s2 = "Kirjuta fail " fullword ascii
    $s3 = "Extrair para" fullword ascii
    $s4 = "Vill du ers" fullword ascii
    $s5 = "elite prepisati datoteko?" fullword ascii
    $s6 = "Extrahera till" fullword ascii
    $s7 = "Vent litt" fullword ascii
    $s8 = "Extrahieren nach" fullword ascii
    $s9 = "6{HAdJ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}