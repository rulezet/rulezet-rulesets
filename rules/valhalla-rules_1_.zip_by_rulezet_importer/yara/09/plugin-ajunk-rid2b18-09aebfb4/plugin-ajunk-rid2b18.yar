rule PLUGIN_AJunk_RID2B18 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file AJunk.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:51:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "AJunk.dll" fullword ascii
      $s2 = "AJunk.DLL" fullword wide
      $s3 = "AJunk Dynamic Link Library" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 560KB and all of them
}