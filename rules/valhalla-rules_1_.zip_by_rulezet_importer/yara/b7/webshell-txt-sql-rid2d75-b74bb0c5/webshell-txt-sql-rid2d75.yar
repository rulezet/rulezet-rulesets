rule Webshell_Txt_Sql_RID2D75 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file Sql.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:32:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cmd=chr(34)&\"cmd.exe /c \"&request.form(\"cmd\")&\" > 8617.tmp\"&chr(34)" fullword ascii
      $s2 = "strQuery=\"dbcc addextendedproc ('xp_regwrite','xpstar.dll')\"" fullword ascii
      $s3 = "strQuery = \"exec master.dbo.xp_cmdshell '\" & request.form(\"cmd\") & \"'\" " fullword ascii
      $s4 = "session(\"login\")=\"\"" fullword ascii
   condition: 
      filesize < 15KB and all of them
}