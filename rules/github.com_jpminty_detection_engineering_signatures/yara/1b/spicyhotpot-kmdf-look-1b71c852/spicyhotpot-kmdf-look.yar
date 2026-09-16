rule SpicyHotPot_KMDF_LOOK {
   meta:
      description = "SpicyHotPot - KMDF_LOOK.sys: Used to identify browser hijacking component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "39764e887fd0b461d86c1be96018a4c2a670b1de90d05f86ed0acb357a683318"
   strings:
      $x1 = "G:\\SVN\\" ascii
      $s1 = "TSWebDownLoadProtect.dll" fullword wide
      $s2 = "ShellIco.dll" fullword wide
      $s3 = "QMLogEx.dll" fullword wide
      $s4 = "SSOCommon.dll" fullword wide
      $s5 = "TsService.exe" fullword ascii
      $s6 = "Hookport.sys" fullword wide
      $s7 = "SafeWrapper32.dll" fullword wide
      $s8 = "safemon.dll" fullword wide
      $s9 = "iNetSafe.dll" fullword wide
      $s10 = "ieplus.dll" fullword wide
      $s11 = "wdui2.dll" fullword wide
      $s12 = "ExtBhoIEToSe.dll" fullword wide
      $s13 = "360NetBase.dll" fullword wide
      $s14 = "urlproc.dll" fullword wide
      $s15 = "360sdbho.dll" fullword wide
      $s16 = "360base.dll" fullword wide
      $s17 = "360UDiskGuard.dll" fullword wide
      $s18 = "TSClinicWebFix.dll" fullword wide
      $s19 = "QMEmKit.dll" fullword wide
      $s20 = "WdHPFileSafe.dll" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 8 of them
}