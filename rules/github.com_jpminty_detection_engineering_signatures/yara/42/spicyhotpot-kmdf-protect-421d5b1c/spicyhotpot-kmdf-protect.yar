rule SpicyHotPot_KMDF_Protect {
   meta:
      description = "SpicyHotPot - KMDF_Protect.sys: Used to identify driver protection and filtering component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "ab0418eb1863c8a2211d06c764f45884c9b7dbd6d1943137fc010b8f3b8d14ae"
   strings:
      $x1 = "wdlogin.exe" fullword wide
      $x2 = "\\Windows\\System32\\cmd.exe" fullword wide
      $x3 = "wuhost.exe" fullword wide
      $x4 = "wrme.exe" fullword wide
      $x5 = "UpdateSelf.exe" fullword ascii
      $x6 = "wccenter.exe" fullword wide
      $s1 = "jCloudScan.dll" fullword wide
      $s2 = "DSFScan.dll" fullword wide
      $s3 = "avescan.dll" fullword wide
      $s4 = "\\Cloudcom2.dll" fullword wide
      $s5 = "\\Cloudcom264.dll" fullword wide
      $s6 = "AVEIEngine.dll" fullword wide
      $s7 = "AVEI.dll" fullword wide
      $s8 = "BAPI.dll" fullword wide
      $s9 = "BAPI64.dll" fullword wide
      $s10 = "360Tray.exe" fullword ascii
      $s11 = "360Safe.exe" fullword ascii
      $s12 = "\\jCloudScan.dll" fullword wide
      $s13 = "\\deepscan64.dll" fullword wide
      $s14 = "\\deepscan.dll" fullword wide
condition:
   uint16(0) == 0x5a4d and filesize < 1000KB and 2 of ($x*) and 6 of ($s*)
}