rule KiwiTaskmgr_2_RID2C0F : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file KiwiTaskmgr.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:33:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
      $s2 = "Kiwi Taskmgr no-gpo" fullword wide
      $s3 = "KiwiAndTaskMgr" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them
}