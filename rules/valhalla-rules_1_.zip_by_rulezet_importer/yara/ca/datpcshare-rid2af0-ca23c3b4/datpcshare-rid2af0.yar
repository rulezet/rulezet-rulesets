rule datPcShare_RID2AF0 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file datPcShare_RID2AF0.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:31:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "PcShare.EXE" fullword wide
      $s2 = "MZKERNEL32.DLL" fullword ascii
      $s3 = "PcShare" fullword wide
      $s4 = "QQ:4564405" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and all of them
}