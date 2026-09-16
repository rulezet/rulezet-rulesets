rule HKTL_rdrbs100_RID2B51 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file rdrbs100.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:01:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "Server address must be IP in A.B.C.D format." 
      $s4 = " mapped ports in the list. Currently " 
   condition: 
      all of them
}