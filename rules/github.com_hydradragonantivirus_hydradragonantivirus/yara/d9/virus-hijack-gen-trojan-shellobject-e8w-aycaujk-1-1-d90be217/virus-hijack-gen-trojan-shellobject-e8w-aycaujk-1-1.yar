rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec1a5fbd6a5ca09382dd4b71f473657eba1a4a6e0982bcd01697821ca24d84f9"

  strings:
    $s1  = "select CommandLine from Win32_Process where Name='{0}'" fullword wide
    $s2  = "Flood! " fullword wide
    $s3  = "%PASS%" fullword wide
    $s4  = "Plugin Error! " fullword wide
    $s5  = "DWN Error! " fullword wide
    $s6  = "_USB Error! " fullword wide
    $s7  = "_PIN Error! " fullword wide
    $s8  = "_KLG Error! " fullword wide
    $s9  = "%DROP%" fullword wide
    $s10 = "%Delay%" fullword wide
    $s11 = "%ANTI%" fullword wide
    $s12 = "Err > Idle" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}