rule Dos_look_RID2A4B : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file look.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 04:56:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<description>CHKen QQ:41901298</description>" fullword ascii
      $s2 = "version=\"9.9.9.9\"" fullword ascii
      $s3 = "name=\"CH.Ken.Tool\"" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 40KB and all of them
}