rule HKTL_EditServer_2_RID2D31 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file EditServer.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:21:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "@HOTMAIL.COM" 
      $s1 = "Press Any Ke" 
      $s3 = "glish MenuZ" 
   condition: 
      all of them
}