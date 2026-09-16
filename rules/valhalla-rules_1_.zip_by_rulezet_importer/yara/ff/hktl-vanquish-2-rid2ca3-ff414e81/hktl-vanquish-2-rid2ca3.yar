rule HKTL_vanquish_2_RID2CA3 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file vanquish.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:57:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "Vanquish - DLL injection failed:" 
   condition: 
      all of them
}