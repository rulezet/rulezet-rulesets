rule Trojan_Hooker_Win32_Floxif_A_14 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b33727cb78e1e453a88c823e77b82253d12415e6a2d5b6e50fa099862cce849"

  strings:
    $x1  = "WMVCore.dll obsolete on this platform, install wmfdist95.exe (contact support@datastead.com to get a download link)" fullword ascii
    $s2  = "failed load QASF.DLL from the system folder, try to (re)register it with regsvr32.exe, or (re)install the Windows Media Format r" ascii
    $s3  = "GDIPLUS.DLL required, download it from" fullword ascii
    $s4  = "QASF.DLL may be obsolete, run dxdiag.exe and verify the version is 11 or higher, otherwise upgrade it" fullword ascii
    $s5  = "visit http://www.datastead.com/WMScriptWriter" fullword ascii
    $s6  = "failed load QASF.DLL from the system folder, try to (re)register it with regsvr32.exe, or (re)install the Windows Media Format r" ascii
    $s7  = "untime 11 from http://support.microsoft.com/kb/946665" fullword ascii
    $s8  = "windowscodec.dll required, install WIC from" fullword ascii
    $s9  = "qedit.dll could be missing or not registered" fullword ascii
    $s10 = "v8.5 build 8.5.2.4 (build 4342) - July 28, 2011 - Copyright " fullword ascii
    $s11 = "profile FASFProfileFromCustomStream is invalid, check it with WMProEdt.exe" fullword ascii
    $s12 = "windowscodecs.dll not installed or not registered" fullword ascii
    $s13 = " is invalid, check it with WMProEdt.exe" fullword ascii
    $s14 = "video will be interlaced at full size when the frame grabber is enabled, unless enabling a deinterlacing (see VideoProcessing_De" ascii
    $s15 = "Invalid owner=This control requires version 4.70 or greater of COMCTL32.DLL&Cannot change the size of a JPEG image" fullword wide
    $s16 = "- Toolbar2000 version 2.1.4/D6, Copyright (C) 1998-2004 by Jordan Russell -" fullword ascii
    $s17 = "process dv data " fullword ascii
    $s18 = "Download it from http://avisynth.org" fullword ascii
    $s19 = "failed to create temp" fullword ascii
    $s20 = "There is no such palette entry.dThis \"Portable Network Graphics\" image contains an unknown critical part which could not be d" wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}