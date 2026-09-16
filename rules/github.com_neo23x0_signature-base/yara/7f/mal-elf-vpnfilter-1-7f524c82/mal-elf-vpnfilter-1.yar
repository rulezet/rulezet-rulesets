rule MAL_ELF_VPNFilter_1 {
   meta:
      description = "Detects VPNFilter malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-05-24"
      hash1 = "f8286e29faa67ec765ae0244862f6b7914fcdde10423f96595cb84ad5cc6b344"
      id = "dc50cb37-a6e7-5eb5-9581-31d7fd005e47"
   strings:
      $s1 = "Login=" fullword ascii
      $s2 = "Password=" fullword ascii
      $s3 = "%s/rep_%u.bin" fullword ascii
      $s4 = "%s:%uh->%s:%hu" fullword ascii
      $s5 = "Password required" fullword ascii 
      $s6 = "password=" fullword ascii 
      $s7 = "Authorization: Basic" fullword ascii 
      $s8 = "/tmUnblock.cgi" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and all of them
}