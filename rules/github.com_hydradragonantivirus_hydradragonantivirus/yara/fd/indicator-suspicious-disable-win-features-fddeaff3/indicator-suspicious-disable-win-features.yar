rule INDICATOR_SUSPICIOUS_Disable_Win_Features {
  meta:
    author      = "Emirhan Ucan"
    description = "Detects disable win features"
    reference   = "625f4bae4d6188fe231c28914281c5000f39117feb70f3847fd1b94951cd15e3 3bdab09c77fda2c0afe9cafd76202cd33f9a1d7adee9e437a931d2ba366ebf87 5dd4ea169cabf9226f54bb53e63ea6a1b5880a0d1222242aee378efb6255b57d 9188c9e15123585764eeaf2664acab784a64c629ad7bde14696788bd4fe9e805 b6ef7d7410a44494a09973b7b0ca173ca4f67f52ea542c7393e3d1874257dfb5"

  strings:
    $k46 = "DisableAutomaticRebootOnCrash" ascii wide
    $k70 = "DisableAutomaticRestartSignOn" ascii wide nocase
    $k47 = "DisableAutomaticRestartScheduledMaintenance" ascii wide
    $k48 = "DisableAutomaticRestartWithLoggedOnUsers" ascii wide
    $k49 = "DisableAutoRebootOnCrash" ascii wide nocase
    $k52 = "DisablePerformanceMonitor" ascii wide nocase
    $k54 = "DisableMMC" ascii wide nocase
    $k55 = "DisableEventViewer" ascii wide nocase
    $k74 = "NoWinKeys" ascii wide nocase
    $k56 = "DisableSnippingTool" ascii wide nocase
    $k57 = "DisableMagnifier" ascii wide nocase
    $k58 = "DisableEaseOfAccess" ascii wide nocase
    $k60 = "DisallowWinPELicensing" ascii wide nocase
    $k61 = "DisableChangeTime" ascii wide nocase
    $r25 = "SOFTWARE\\McAfee" ascii wide
    $k62 = "bDisableSelfProtection" ascii wide nocase
    $r26 = "SOFTWARE\\AVG" ascii wide
    $k63 = "DisableAv" ascii wide nocase
    $r27 = "SOFTWARE\\Bitdefender" ascii wide
    $k64 = "BlockUserModeAccess" ascii wide nocase
    $k66 = "AntiVirusOverride" ascii wide nocase
    $k67 = "disablelogonbar" ascii wide nocase
    $r30 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide
    $k68 = "DisableScanOnRealTimeEnable" ascii wide nocase
    $k69 = "DisableAntiSpyware" ascii wide nocase
    $k72 = "DisableWinDefender" ascii wide nocase
    $r31 = "SOFTWARE\\Microsoft\\Windows Defender" ascii wide
    $k71 = "DisableAntiSpyware" ascii wide nocase
    $k75 = "DisableAntivirus" ascii wide nocase
    $k73 = "NoAutoUpdate" ascii wide nocase
    $k76 = "aswidsagenta" ascii wide nocase
    $k77 = "DisableAv" ascii wide nocase
    $k78 = "BlockUserModeAccess" ascii wide nocase
    $k79 = "bDisableSelfProtection" ascii wide nocase
    $k80 = "ProtectEnabled" ascii wide nocase
    $k81 = "MalwareProtectionEnabled" ascii wide nocase
    $k82 = "ProductEnabled" ascii wide nocase
    $k83 = "DisablePowerShell" ascii wide nocase
    $k84 = "NoViewContextMenu" ascii wide nocase
    $k85 = "NoRunAs" ascii wide nocase
    $k91 = "NoFileOpen" ascii wide nocase
    $r20 = "SOFTWARE\\Policies\\Microsoft\\Windows\\System" ascii wide
    $r22 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide
    $r23 = "SYSTEM\\CurrentControlSet\\Control\\MiniNT" ascii wide
    $r50 = "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" ascii wide
    $r37 = "SYSTEM\\ControlSet001\\Control\\Keyboard Layouts\\Scancode Map" ascii wide
    $r33 = "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell" ascii wide
    $h16 = "gdi32dll" ascii wide nocase
    $h19 = "efi.h" ascii wide nocase
    $h20 = "protonme" ascii wide nocase
    $h21 = "discordnitro" ascii wide nocase
    $h26 = "appxalluserstore" ascii wide nocase
    $h27 = "wextracmui" ascii wide nocase
    $h28 = "Yourfileshasbeenencrypted" ascii wide nocase
    $h29 = "bootmgfw.efi" ascii wide nocase
    $h30 = "memztrojan" ascii wide nocase
    $h32 = "FINAL WARNING" ascii wide nocase
    $h33 = "executed a Trojan" ascii wide nocase

  condition:
    uint16(0) == 0x5a4d and
    (2 of ($r*) or 3 of ($k*)) or      (2 of ($h*))
}