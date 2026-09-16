rule Webshell_RhV_webshell_RID2F6B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file webshell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:56:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "RhViRYOzz" 
      $s1 = "d\\O!jWW" 
      $s2 = "bc!jWW" 
      $s3 = "0W[&{l" 
      $s4 = "[INhQ@\\" 
   condition: 
      all of them
}