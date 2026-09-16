rule SwitchSniffer_RID2C50 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file SwitchSniffer_RID2C50.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:43:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "NextSecurity.NET" fullword wide
      $s2 = "SwitchSniffer_RID2C50 Setup" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of them
}