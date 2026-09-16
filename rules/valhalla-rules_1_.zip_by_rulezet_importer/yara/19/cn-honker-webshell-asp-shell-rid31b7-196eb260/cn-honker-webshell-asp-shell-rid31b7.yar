rule CN_Honker_Webshell_ASP_shell_RID31B7 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file shell.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:34:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "xPost.Open \"GET\",\"http://www.i0day.com/1.txt\",False //" fullword ascii
      $s2 = "sGet.SaveToFile Server.MapPath(\"test.asp\"),2 //" fullword ascii
      $s3 = "http://hi.baidu.com/xahacker/fuck.txt" fullword ascii
   condition: 
      filesize < 1KB and all of them
}