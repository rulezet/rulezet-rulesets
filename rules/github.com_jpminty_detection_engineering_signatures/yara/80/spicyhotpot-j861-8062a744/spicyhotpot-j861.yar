rule SpicyHotPot__J861 {
   meta:
      description = "SpicyHotPot - _J861.exe: Used to identify system fingerprinting, enumeration and networking component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "c83e6b96ee3aa1a580157547eae88d112d2202d710218f2ed496f7fe3d861abc"
   strings:
      $x1 = "E:\\work\\Icon_Report\\Release\\_service.pdb" fullword ascii
      $x2 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii
      $x3 = "https://du.testjj.com/api/v1/id" fullword ascii
      $s1 = "SEC_E_ILLEGAL_MESSAGE (0x%08X)" ascii
      $s2 = "Failed reading the chunked-encoded stream" fullword ascii
      $s3 = "Negotiate: noauthpersist -> %d, header part: %s" fullword ascii
      $s4 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s5 = "schannel: CertGetNameString() failed to match connection hostname (%s) against server certificate names" fullword ascii
      $s6 = "failed to load WS2_32.DLL (%u)" fullword ascii
      $s7 = "/c ping -n 3 127.1 >nul & del /q %s" fullword ascii
      $s8 = "No more connections allowed to host %s: %zu" fullword ascii
      $s9 = "%d ReadPhysicalDriveInNTUsingSmart ERROR DeviceIoControl(%d, SMART_GET_VERSION) returned 0, error is %d" fullword ascii
      $s10 = "%d ReadPhysicalDriveInNTWithAdminRights ERROR DeviceIoControl() %d, DFP_GET_VERSION) returned 0, error is %d" fullword ascii
      $s11 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii
      $s12 = "Content-Type: %s%s%s" fullword ascii
      $s13 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii
      $s14 = "No valid port number in connect to host string (%s)" fullword ascii
      $s15 = "Excess found in a read: excess = %zu, size = %I64d, maxdownload = %I64d, bytecount = %I64d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 2 of ($x*) and 8 of ($s*)
}