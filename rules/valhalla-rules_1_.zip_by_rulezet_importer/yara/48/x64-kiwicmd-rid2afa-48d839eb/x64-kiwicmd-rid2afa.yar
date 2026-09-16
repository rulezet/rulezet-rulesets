rule x64_KiwiCmd_RID2AFA : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file KiwiCmd.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:46:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
      $s2 = "Kiwi Cmd no-gpo" fullword wide
      $s3 = "KiwiAndCMD" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 2 of them
}