rule client32 {
  meta:
    description = "19438 - file client32.ini"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
    date        = "2023-10-29"
    hash1       = "bba34ad7183d7911f7f2c53bfe912d315d0e44d7aa0572963dc003d063130e85"

  strings:
    $s1  = "ValidAddresses.TCP=*" fullword ascii
    $s2  = "Filename=C:\\ProgramData\\SchCache\\client32u.ini" fullword ascii
    $s3  = "SecondaryPort=133" fullword ascii
    $s4  = "SecurityKey2=dgAAAJ8zaIwMzh8Mk59(swLsFIUA" fullword ascii
    $s5  = "Port=133" fullword ascii
    $s6  = "Usernames=*" fullword ascii
    $s7  = "[HTTP]" fullword ascii
    $s8  = "Protocols=2,3" fullword ascii
    $s9  = "DisableChatMenu=1" fullword ascii
    $s10 = "SKMode=1" fullword ascii
    $s11 = "quiet=1" fullword ascii
    $s12 = "DisableRequestHelp=1" fullword ascii
    $s13 = "DisableChat=1" fullword ascii
    $s14 = "HideWhenIdle=1" fullword ascii
    $s15 = "DisableAudioFilter=1" fullword ascii
    $s16 = "SysTray=0" fullword ascii
    $s17 = "DisableReplayMenu=1" fullword ascii
    $s18 = "DisableDisconnect=1" fullword ascii
    $s19 = "[_License]" fullword ascii
    $s20 = "GSK=FK;O@GCPGA:F=JBEGK<H@LEK:C?BDF" fullword ascii

  condition:
    uint16(0) == 0x7830 and filesize < 1KB and
    8 of them
}