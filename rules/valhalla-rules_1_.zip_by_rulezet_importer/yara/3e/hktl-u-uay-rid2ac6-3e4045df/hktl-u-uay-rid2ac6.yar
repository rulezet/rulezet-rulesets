rule HKTL_u_uay_RID2AC6 : DEMO HKTL T1505_003 T1543_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file uay.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 08:21:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, T1543_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "exec \"c:\\WINDOWS\\System32\\freecell.exe" 
      $s9 = "SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Security" 
   condition: 
      1 of them
}