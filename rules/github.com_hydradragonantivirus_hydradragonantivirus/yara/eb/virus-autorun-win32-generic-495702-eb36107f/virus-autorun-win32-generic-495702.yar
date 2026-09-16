rule Virus_Autorun_Win32_Generic_495702 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Generic.495702.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad0cdc8c7a5841539c68fe013ade0dbf8222216f408224cf261a60fee3929d6b"

  strings:
    $s1  = "Content-Location:File://foo.exe" fullword ascii
    $s2  = "</script>MIME-Version: 1.0<body bgcolor=black scroll=no>" fullword ascii
    $s3  = "111111-1111-1111-1111-111111111111\"  CODEBASE=\"mhtml:'+path+'\\\\message.html!File://foo.exe\"></OBJECT>')" fullword ascii
    $s4  = "</script><body bgcolor=black scroll=no>" fullword ascii
    $s5  = "document.write(' <title>Message</title><body scroll=no bgcolor=white><FONT face=\"Arial\" color=black style=\"position:absolute;" ascii
    $s6  = "document.write(' <title>Message</title><body scroll=no bgcolor=white><FONT face=\"Arial\" color=black style=\"position:absolute;" ascii
    $s7  = "<body bgcolor=black scroll=no>" fullword ascii
    $s8  = "<body bgcolor=black scr" fullword ascii
    $s9  = "function malware()" fullword ascii
    $s10 = "FONT f" fullword ascii
    $s11 = ":20;left:90;z-index:100; font-size:12px;\">No message</center><OBJECT style=\"cursor:cross-hair\" alt=\"moo ha ha\" CLASSID=\"CL" ascii
    $s12 = "path=unescape(path);" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}