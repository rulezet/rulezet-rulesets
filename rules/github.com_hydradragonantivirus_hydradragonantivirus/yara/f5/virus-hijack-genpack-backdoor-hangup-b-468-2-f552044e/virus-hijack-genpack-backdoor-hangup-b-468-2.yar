rule Virus_Hijack_GenPack_Backdoor_Hangup_B_468_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_468_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f96d829e86c703e1dc71b3356944c47c4d496c607cb93249e1d11161b15b8eea"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "Copyright (c) Youku.com. All rights reserved." fullword wide
    $s3 = "el=\"requireAdministrator\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-" ascii
    $s4 = "+ALIBABA (CHINA) NETWORK TECHNOLOGY CO.,LTD.1402" fullword ascii
    $s5 = "+ALIBABA (CHINA) NETWORK TECHNOLOGY CO.,LTD.0" fullword ascii
    $s6 = "soft-com:compatibility.v1\"><application><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f676c76" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}