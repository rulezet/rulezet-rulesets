rule SUSP_ZIP_LNK_PhishAttachment_Pattern_Jun22_1 {
   meta:
      description = "Detects suspicious tiny ZIP files with phishing attachment characteristics"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2022-06-23"
      score = 65
      hash1 = "4edb41f4645924d8a73e7ac3e3f39f4db73e38f356bc994ad7d03728cd799a48"
      hash2 = "c4fec375b44efad2d45c49f30133efbf6921ce82dbb2d1a980f69ea6383b0ab4"
      hash3 = "9c70eeac97374213355ea8fa019a0e99e0e57c8efc43daa3509f9f98fa71c8e4"
      hash4 = "ddc20266e38a974a28af321ab82eedaaf51168fbcc63ac77883d8be5200dcaf9"
      hash5 = "b59788ae984d9e70b4f7f5a035b10e6537063f15a010652edd170fc6a7e1ea2f"
      id = "3537c4ea-a51d-5100-97d7-71a24da5ff43"
   strings:
      $sl1 = ".lnk" 
   condition:
      uint16(0) == 0x4b50 and 
      filesize < 2KB and 
      $sl1 in (filesize-256..filesize)
}