import "pe"
rule _Virus_Hijack_Dropped_Backdoor_Padodor_BJ_683_1_Virus_Sysbot_Tro_142 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Dropped.Backdoor.Padodor.BJ_683_1.vir, Virus.Sysbot_Trojan.GenericKDZ.105157.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "520f541ef6c86ca0d365d3ed63a2f7eadb6ad690de4b0dbacf69ea4d4984648e"
    hash2       = "6d34c78b180f8e96fe8d40cd2a3df7f3bdca39d84f7999d1a5fedf4f0213bd67"

  strings:
    $x1  = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\avscan.exe" fullword wide
    $x2  = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\setup.exe" fullword wide
    $x3  = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\install.exe" fullword wide
    $x4  = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\setup32.exe" fullword wide
    $x5  = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\PCMAV.exe" fullword wide
    $x6  = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\PCMAV-CLN.exe" fullword wide
    $x7  = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\PCMAV-RTP.exe" fullword wide
    $x8  = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\PCMAV-SE.exe" fullword wide
    $x9  = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ansav.exe" fullword wide
    $x10 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\avgnt.exe" fullword wide
    $x11 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SMP.exe" fullword wide
    $x12 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Avguard.exe" fullword wide
    $x13 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Avgnt.exe" fullword wide
    $x14 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Avgw.exe" fullword wide
    $x15 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\CClaw.exe" fullword wide
    $x16 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Nip.exe" fullword wide
    $x17 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Nipsvc.exe" fullword wide
    $x18 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Niu.exe" fullword wide
    $x19 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Njeeves.exe" fullword wide
    $x20 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Nvccf.exe" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "3af0cc49b5eb0ba06a2417243862a798" and (1 of ($x*))
    ) or (all of them)
}