rule Trojan_Hooker_Win32_Floxif_A_58 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_58.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c4e40d97f8470102a6e2d7f5c37588a6a4d0476284e98e8bf1dd07c736957df"

  strings:
    $s1  = "command processor" fullword ascii
    $s2  = "Unable to get mutex %s." fullword ascii
    $s3  = "Unable to get Primary Domain from MAILSCAN.INI!!!" fullword ascii
    $s4  = "Session Not Ready and Unable to get PID of Explorer.exe!" fullword ascii
    $s5  = "GetIPFromHost fails!!! DNS may be down." fullword ascii
    $s6  = "[%d] Command bef mod: %s" fullword ascii
    $s7  = "OpenProcessToken Failed! Reason: %s" fullword ascii
    $s8  = "[%d] Command aft mod: %s" fullword ascii
    $s9  = "OpenProcess Failed On %d! Reason: %s" fullword ascii
    $s10 = "[%d] Command mode started" fullword ascii
    $s11 = "ERROR!!! Unable to Move TCM file (%s) to CMD! Reason above. Moving it to ERR." fullword ascii
    $s12 = "Unable to load CrashReport.dll." fullword ascii
    $s13 = "ERROR!!! Exception in SelectEntry. Description = %s" fullword ascii
    $s14 = "ERROR!!! Unable to Move MES file (%s) to MSG! Reason above. Renaming it to .MER file" fullword ascii
    $s15 = "Error receiving line from lower layer for command [%s]!" fullword ascii
    $s16 = "MyRegOpenKey fails on key %s!!! Reason %s" fullword ascii
    $s17 = "ERROR!!! Exception in OpenDatabase. Description = %s" fullword ascii
    $s18 = "ERROR!!! Unable to delete the key %s! Reason: %s" fullword ascii
    $s19 = "[CSID] Error getting SID for Username(%u): %s [SessID:%u]" fullword ascii
    $s20 = "ERROR!!! Exception in InsertEntry. Description = %s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}