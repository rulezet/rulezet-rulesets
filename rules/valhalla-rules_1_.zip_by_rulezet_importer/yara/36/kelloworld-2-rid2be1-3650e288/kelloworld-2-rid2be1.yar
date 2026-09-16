rule kelloworld_2_RID2BE1 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file kelloworld.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:25:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Hello World!" fullword wide
      $s2 = "kelloworld.dll" fullword ascii
      $s3 = "kelloworld de mimikatz pour Windows" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them
}