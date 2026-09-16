import "pe"
rule _Trojan_Hooker_Win32_Floxif_A_10_Trojan_Hooker_Win32_Floxif_A_32_242 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Win32.Floxif.A_10.vir, Trojan.Hooker_Win32.Floxif.A_32.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a8a0da736dd0d3c25fc5a39411ee658bcc5e1bf54652a9ac5cf27c39e5fd691"
    hash2       = "4601262fb2c03cbd92270fdd6851c5911bc6d333c7fb09cf2b2a41e3bbfa6c4a"

  strings:
    $x1  = "RunMUpdate : SetEvent (%s) and Don't Execute mupdate2.exe" fullword ascii
    $x2  = "[%s] Create MiniDumpFile, DbgHelp.dll Load Fail (error = %d)" fullword ascii
    $s3  = "[PostCheckService] Fail to Change AppExp Service's start type %d -> %d" fullword ascii
    $s4  = "[mautoup] Cannot execute : parent process %s (%s)" fullword ascii
    $s5  = "[CreateMautoupMutex] MAutoup CreateMutex Fail (%s)" fullword ascii
    $s6  = "[MassUP] Fail: Mutex Already Exists." fullword ascii
    $s7  = "-RegGetString64(0x%0X) : bWin64 - %d : Return %d" fullword ascii
    $s8  = "[%s] Create MiniDumpFile, CreatFile Fail (Path = %s error = %d)" fullword ascii
    $s9  = "[PostCheckService] Change AppExp Service's StartType %d -> %d" fullword ascii
    $s10 = "[SafeExtractOrCopyFile_CopyFile] [fail] (%s -> %s) (GetLastError()=%d)" fullword ascii
    $s11 = "[SafeExtractOrCopyFile_Extract] [fail] (%s -> %s) (GetLastError()=%d)" fullword ascii
    $s12 = "[MassUP] Exception Executed!!" fullword ascii
    $s13 = "[CreateMautoupMutex] MAutoup Mutex Name (%s)" fullword ascii
    $s14 = "CopyMUpdateFiles : Backup File Fail. (%s, %s)(GetLastErr: %d)" fullword ascii
    $s15 = "[PreCheckService] Fail to Change AppExp Service's start type  %d -> %d" fullword ascii
    $s16 = "[%s] Create MiniDumpFile, Path = %s" fullword ascii
    $s17 = "[CreateMautoupMutex] MAutoup already runnning...(%s)" fullword ascii
    $s18 = "[RollBackSelfUpdate] SetFileAttributes Fail. (%s)(GetLastErr: %d)" fullword ascii
    $s19 = "WaitForMUpdateQuit : Success to create MUpdate2's mutex." fullword ascii
    $s20 = "[RollBackSelfUpdate] DeleteFile Success - File was not Back-Up. (%s)" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "a03bdeee8d38d74acb57a3cec52cc09f" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}