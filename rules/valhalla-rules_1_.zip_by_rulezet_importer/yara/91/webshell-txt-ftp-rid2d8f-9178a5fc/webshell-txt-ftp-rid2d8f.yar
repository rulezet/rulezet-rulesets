rule Webshell_Txt_ftp_RID2D8F : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file ftp.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:37:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "';exec master.dbo.xp_cmdshell 'echo open " ascii
      $s2 = "';exec master.dbo.xp_cmdshell 'ftp -s:';" ascii
      $s3 = "';exec master.dbo.xp_cmdshell 'echo get lcx.exe" ascii
      $s4 = "';exec master.dbo.xp_cmdshell 'echo get php.exe" ascii
      $s5 = "';exec master.dbo.xp_cmdshell 'copy " ascii
      $s6 = "ftp -s:d:\\ftp.txt " fullword ascii
      $s7 = "echo bye>>d:\\ftp.txt " fullword ascii
   condition: 
      filesize < 2KB and 2 of them
}