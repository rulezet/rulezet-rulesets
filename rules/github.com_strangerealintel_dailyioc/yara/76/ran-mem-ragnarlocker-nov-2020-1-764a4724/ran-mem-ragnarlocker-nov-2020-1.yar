rule Ran_Mem_RagnarLocker_Nov_2020_1 {
   meta:
      description = "Detect memory artefacts of the Ragnarlocker ransomware (Nov 2020)"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-11-26"
      hash1 = "041fd213326dd5c10a16caf88ff076bb98c68c052284430fba5f601023d39a14"
      hash2 = "dd79b2abc21e766fe3076038482ded43e5069a1af9e0ad29e06dce387bfae900"
   strings:
      $s1 = "\\\\.\\PHYSICALDRIVE%d" fullword wide
      $s2 = "bootfont.bin" fullword wide
      $s3 = "bootsect.bak" fullword wide
      $s4 = "bootmgr.efi" fullword wide
      $s5 = "---RAGNAR SECRET---" fullword ascii
      $s6 = "Mozilla" 
      $s7 = "Internet Explorer" fullword wide 
      $s8 = "  </trustInfo>" fullword ascii
      $s9 = "Tor browser" fullword wide
      $s10 = "Opera Software" fullword wide 
      $s11 = "---END RAGN KEY---" fullword ascii
      $s12 = "---BEGIN RAGN KEY---" fullword ascii
      $s13 = "%s-%s-%s-%s-%s" fullword wide
      $s14 = "$Recycle.Bin" fullword wide 
      $s15 = "***********************************************************************************" fullword ascii
      $s16 = "K<^_[]" fullword ascii
      $s17 = "SD;SDw" fullword ascii
      $s18 = "Windows.old" fullword wide 
      $s19 = "iconcache.db" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize > 30KB and 12 of them 
}