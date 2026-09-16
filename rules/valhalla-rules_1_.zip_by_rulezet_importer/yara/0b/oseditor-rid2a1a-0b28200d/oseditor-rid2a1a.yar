rule OSEditor_RID2A1A : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file OSEditor_RID2A1A.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 03:35:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "OSEditor_RID2A1A.exe" fullword wide
      $s2 = "netsafe" wide
      $s3 = "OSC Editor" fullword wide
      $s4 = "GIF89" ascii
      $s5 = "Unlock" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them
}