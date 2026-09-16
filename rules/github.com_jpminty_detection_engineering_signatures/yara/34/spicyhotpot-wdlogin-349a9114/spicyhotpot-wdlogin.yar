rule SpicyHotPot_wdlogin {
   meta:
      description = "SpicyHotPot - wdlogin.exe: Used to identify memory dump uploading component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "7c0fdee3670cc53a22844d691307570a21ae3be3ce4b66e46bb6d9baad1774b8"
   strings:
      $x1 = "D:\\Work\\Install_Driver\\Driver_helper\\Release\\wdlogin.pdb" fullword ascii
      $x2 = "kmdf_protect.sys" fullword ascii
      $x3 = "kmdf_look.sys" fullword ascii
      $x4 = "/api/v1/post_dump" fullword ascii
      $s1 = "Negotiate: noauthpersist -> %d, header part: %s" fullword ascii
      $s2 = "https://db.testyk.com" fullword ascii
      $s3 = "https://da.testiu.com" fullword ascii
      $s4 = "https://du.testjj.com" fullword ascii
      $s5 = "schannel: CertGetNameString() failed to match connection hostname (%s) against server certificate names" fullword ascii
      $s6 = "No more connections allowed to host %s: %zu" fullword ascii
      $s7 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii
      $s8 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii
      $s9 = "dumping" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of ($x*) and 3 of ($s*)
}