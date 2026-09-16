rule SpicyHotPot_wrme {
   meta:
      description = "SpicyHotPot - wrme.exe: Used to identify module starting and reporting component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "7e489f1f72cac9f1c88bdc6be554c78b5a14197d63d1bae7e41de638e903af21"
   strings:
      $x1 = "DvUpdate.exe" fullword ascii
      $x2 = "D:\\Work\\Install_Driver\\Driver_helper\\Release\\wrme.pdb" fullword ascii
      $x3 = "No more connections allowed to host %s: %zu" fullword ascii
      $s1 = "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs when a fatal SSL/TLS alert is received (e.g. handshake failed). More " ascii
      $s2 = "Failed reading the chunked-encoded stream" fullword ascii
      $s3 = "Content-Type: %s%s%s" fullword ascii
      $s4 = "Excess found in a read: excess = %zu, size = %I64d, maxdownload = %I64d, bytecount = %I64d" fullword ascii
      $s5 = "Negotiate: noauthpersist -> %d, header part: %s" fullword ascii
      $s6 = "https://db.testyk.com" fullword ascii
      $s7 = "https://da.testiu.com" fullword ascii
      $s8 = "https://du.testjj.com" fullword ascii
      $s9 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s10 = "schannel: CertGetNameString() failed to match connection hostname (%s) against server certificate names" fullword ascii
      $s11 = "failed to load WS2_32.DLL (%u)" fullword ascii
      $s12 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii
      $s13 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 2 of ($x*) and 7 of ($s*)
}