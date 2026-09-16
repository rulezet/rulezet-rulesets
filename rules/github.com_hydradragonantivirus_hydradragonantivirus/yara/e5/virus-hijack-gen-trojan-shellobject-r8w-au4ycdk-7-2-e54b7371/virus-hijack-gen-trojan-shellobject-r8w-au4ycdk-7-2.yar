rule Virus_Hijack_Gen_Trojan_ShellObject_r8W_au4YcDk_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r8W@au4YcDk_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df4a8add2f5fc9a79e94e129c8f4fc545e190fc77be0922c872345d2ed23a111"

  strings:
    $s1 = "Heck, I don't know$Configure Solitaire for screen shots" fullword wide
    $s2 = ": %Developed for Microsoft by Wes Cherry" fullword wide
    $s3 = "Set game number" fullword wide
    $s4 = "Force a win" fullword wide
    $s5 = "Solitaire Game Applet" fullword wide
    $s6 = "Print # of cards in each col" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}