rule IISPutScannesr_RID2C6C : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file IISPutScannesr_RID2C6C.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:48:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "yoda & M.o.D." ascii
      $s2 = "-> come.to/f2f **************" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and all of them
}