import "pe"
rule _Virus_Delself_Win32_Worm_VB_AND_Virus_Delself_Win32_Worm_VB_AND_373 {
  meta:
    description = "datamaliciousorder - from files Virus.Delself_Win32.Worm.VB.AND.vir, Virus.Delself_Win32.Worm.VB.AND_1.vir, Virus.Hijack_Win32.Worm.VB.AND.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b0b524939b546bf9ac84f8af3eea669520d1410bc1de97a8d9058b19244a92f"
    hash2       = "d94d1e819fc104afc753978cac062e125d4bcbc4b0b6515c8424d082c4f9f461"
    hash3       = "e6c09a6e931ba6034d6f96d4487ee7a83382961aedc299ed3a9b686756ac0080"

  strings:
    $x1  = "cmd.exe  /c net user helpassistant 123456" fullword wide
    $x2  = "cmd.exe  /c net start TlntSvr" fullword wide
    $x3  = "cmd.exe  /c net stop sharedaccess" fullword wide
    $x4  = "cmd.exe  /c net stop wuauserv" fullword wide
    $x5  = "cmd.exe  /c net stop srservice" fullword wide
    $x6  = "cmd.exe  /c net stop wscsvc" fullword wide
    $s7  = "sc config srservice start= disabled" fullword wide
    $s8  = "sc config SharedAccess start= disabled" fullword wide
    $s9  = "sc config wuauserv start= disabled" fullword wide
    $s10 = "sc config wscsvc start= disabled" fullword wide
    $s11 = " Section Name" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "634dedd3d9e87ec17ec29bd42899975e" and (1 of ($x*) and all of them)
    ) or (all of them)
}