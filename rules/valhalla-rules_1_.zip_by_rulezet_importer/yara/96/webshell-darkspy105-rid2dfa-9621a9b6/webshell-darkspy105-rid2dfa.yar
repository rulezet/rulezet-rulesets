rule Webshell_DarkSpy105_RID2DFA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file DarkSpy105.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:54:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "Sorry,DarkSpy got an unknown exception,please re-run it,thanks!" 
   condition: 
      all of them
}