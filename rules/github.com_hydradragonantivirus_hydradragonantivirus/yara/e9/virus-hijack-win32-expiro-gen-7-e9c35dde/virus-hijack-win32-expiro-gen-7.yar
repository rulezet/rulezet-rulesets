rule Virus_Hijack_Win32_Expiro_Gen_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Expiro.Gen.7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb6e1cba6f7929491d7f5b61167b5dd49ec164ed5875029d4ff2f653be00799c"

  strings:
    $s1  = "Update Failed : To Download Database" fullword wide
    $s2  = "Auto-Update Failed, GoTo Smadav.net to update manually" fullword wide
    $s3  = "Update Failed : Installation Not Found" fullword wide
    $s4  = "Update File Error" fullword wide
    $s5  = "Update Failed : To Replace File" fullword wide
    $s6  = "Progress :" fullword ascii
    $s7  = "<link rel=" fullword wide
    $s8  = "Update Success : Full Update" fullword wide
    $s9  = "Update Aborted" fullword wide
    $s10 = "No Update Found" fullword wide
    $s11 = "Update Success : " fullword wide
    $s12 = "Checking Updates (Retry #" fullword wide
    $s13 = "Exit (" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}