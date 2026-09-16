rule Webshell_EFSO_2_asp_RID2E07 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file EFSO_2.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 10:57:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Ejder was HERE" 
      $s1 = "*~PU*&BP[_)f!8c2F*@#@&~,P~P,~P&q~8BPmS~9~~lB~X`V,_,F&*~,jcW~~[_c3TRFFzq@#@&PP,~~" 
   condition: 
      2 of them
}