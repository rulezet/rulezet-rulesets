rule WebCrack4_RouterPasswordCracking_RID339C : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file WebCrack4-RouterPasswordCracking.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 14:55:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "http://www.site.com/test.dll?user=%USERNAME&pass=%PASSWORD" fullword ascii
      $s1 = "Username: \"%s\", Password: \"%s\", Remarks: \"%s\"" fullword ascii
      $s14 = "user:\"%s\" pass: \"%s\" result=\"%s\"" fullword ascii
      $s16 = "Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)" fullword ascii
      $s20 = "List count out of bounds (%d)+Operation not allowed on sorted string list%String" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 5000KB and 2 of them
}