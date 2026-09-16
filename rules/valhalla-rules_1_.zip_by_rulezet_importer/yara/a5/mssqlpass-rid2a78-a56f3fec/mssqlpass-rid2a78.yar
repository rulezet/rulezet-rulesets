rule MSSqlPass_RID2A78 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file MSSqlPass_RID2A78.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 06:11:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Reveals the passwords stored in the Registry by Enterprise Manager of SQL Server" wide
      $s1 = "empv.exe" fullword wide
      $s2 = "Enterprise Manager PassView" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 120KB and all of them
}