rule CN_Tools_Shiell_RID2CD2 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file Shiell.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:05:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\Users\\Tong\\Documents\\Visual Studio 2012\\Projects\\Shift shell" ascii
      $s2 = "C:\\Windows\\System32\\Shiell.exe" fullword wide
      $s3 = "Shift shell.exe" fullword wide
      $s4 = "\" /v debugger /t REG_SZ /d \"" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1500KB and 2 of them
}