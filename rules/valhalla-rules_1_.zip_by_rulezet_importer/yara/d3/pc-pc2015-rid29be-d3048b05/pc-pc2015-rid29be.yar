rule Pc_pc2015_RID29BE : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file pc2015.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 01:01:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\svchost.exe" ascii
      $s1 = "LON\\OD\\O-\\O)\\O%\\O!\\O=\\O9\\O5\\O1\\O" fullword ascii
      $s8 = "%s%08x.001" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 309KB and all of them
}