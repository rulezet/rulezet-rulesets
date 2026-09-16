rule HKTL_by063cli_RID2B4F : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file by063cli.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:01:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "#popmsghello,are you all right?" 
      $s4 = "connect failed,check your network and remote ip." 
   condition: 
      all of them
}