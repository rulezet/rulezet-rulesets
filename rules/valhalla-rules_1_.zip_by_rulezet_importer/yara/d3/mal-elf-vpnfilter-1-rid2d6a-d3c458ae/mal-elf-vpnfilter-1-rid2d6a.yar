rule MAL_ELF_VPNFilter_1_RID2D6A : APT DEMO FILE LINUX MAL {
   meta:
      description = "Detects VPNFilter malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-24 10:30:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f8286e29faa67ec765ae0244862f6b7914fcdde10423f96595cb84ad5cc6b344"
      tags = "APT, DEMO, FILE, LINUX, MAL"
      minimum_yara = "3.5.0"
      
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
      uint16 ( 0 ) == 0x457f and filesize < 100KB and all of them
}