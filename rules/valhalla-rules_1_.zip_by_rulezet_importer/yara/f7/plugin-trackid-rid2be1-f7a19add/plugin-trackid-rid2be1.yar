rule PLUGIN_TracKid_RID2BE1 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file TracKid.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:25:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "E-mail: cracker_prince@163.com" fullword ascii
      $s1 = ".\\TracKid Log\\%s.txt" fullword ascii
      $s2 = "Coded by prince" fullword ascii
      $s3 = "TracKid.dll" fullword ascii
      $s4 = ".\\TracKid Log" fullword ascii
      $s5 = "%08x -- %s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 3 of them
}