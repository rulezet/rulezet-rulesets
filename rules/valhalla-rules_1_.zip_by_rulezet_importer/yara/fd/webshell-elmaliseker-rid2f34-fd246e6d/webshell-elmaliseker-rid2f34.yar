rule Webshell_elmaliseker_RID2F34 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file elmaliseker.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:47:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "javascript:Command('Download'" 
      $s5 = "zombie_array=array(" 
   condition: 
      all of them
}