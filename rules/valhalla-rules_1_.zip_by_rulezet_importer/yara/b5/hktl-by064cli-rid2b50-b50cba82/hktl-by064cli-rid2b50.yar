rule HKTL_by064cli_RID2B50 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file by064cli.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:01:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "packet dropped,redirecting" 
      $s9 = "input the password(the default one is 'by')" 
   condition: 
      all of them
}