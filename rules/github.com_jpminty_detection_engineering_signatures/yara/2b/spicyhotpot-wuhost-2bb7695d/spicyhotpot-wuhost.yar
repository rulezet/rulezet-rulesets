rule SpicyHotPot_wuhost {
   meta:
      description = "SpicyHotPot - wuhost.exe: Used to identify rootkit and module updating component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "eb54cd2d61507b9e98712de99834437224b1cef31a81544a47d93e470b8613fc"
   strings:
      $x1 = "wdlogin.exe" fullword ascii
      $x2 = "UpdateTemp.exe" fullword ascii
      $x3 = "UpdateSelf.exe" fullword ascii
      $x4 = "wrme.exe" fullword ascii
      $x5 = "wccenter.exe" fullword ascii
      $x6 = "D:\\Work\\Install_Driver\\Driver_helper\\Release\\wuhost.pdb" fullword ascii
      $x7 = "wuhost.exe" fullword ascii
      $s1 = "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs when a fatal SSL/TLS alert is received (e.g. handshake failed). More " ascii
      $s2 = "Failed reading the chunked-encoded stream" fullword ascii
      $s3 = "Negotiate: noauthpersist -> %d, header part: %s" fullword ascii
      $s4 = "https://db.testyk.com" fullword ascii
      $s5 = "https://da.testiu.com" fullword ascii
      $s6 = "https://du.testjj.com" fullword ascii
      $s7 = "dump_temp" fullword ascii
      $s8 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s9 = "schannel: CertGetNameString() failed to match connection hostname (%s) against server certificate names" fullword ascii
      $s10 = "failed to load WS2_32.DLL (%u)" fullword ascii
      $s11 = "No more connections allowed to host %s: %zu" fullword ascii
      $s12 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 2 of ($x*) and 4 of them
}