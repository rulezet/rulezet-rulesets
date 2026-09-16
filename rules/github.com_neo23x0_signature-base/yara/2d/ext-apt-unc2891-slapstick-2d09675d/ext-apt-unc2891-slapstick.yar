rule EXT_APT_UNC2891_SLAPSTICK {
   meta:
      author = "Mandiant"
      description = "Detects SLAPSTICK malware used by UNC2891"
      date = "2022-03-17"
      reference = "https://www.mandiant.com/resources/blog/unc2891-overview"
      score = 80
   strings:
      $ss1 = { 25 59 20 25 62 20 25 64 20 25 48 3a 25 4d 3a 25 53 20 20 20 20 00 }
      $ss2 = { 25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 00 }
      $ss3 = { 25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 20 25 73 0a 00 }
   condition:
      (uint32(0) == 0x464c457f) and all of them
}