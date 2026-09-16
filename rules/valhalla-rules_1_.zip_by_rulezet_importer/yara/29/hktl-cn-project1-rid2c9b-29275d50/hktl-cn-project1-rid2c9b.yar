rule HKTL_CN_Project1_RID2C9B : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file Project1.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:56:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "EXEC master.dbo.sp_addextendedproc 'xp_cmdshell','xplog70.dll'" fullword ascii
      $s2 = "Password.txt" fullword ascii
      $s3 = "LoginPrompt" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 5000KB and all of them
}