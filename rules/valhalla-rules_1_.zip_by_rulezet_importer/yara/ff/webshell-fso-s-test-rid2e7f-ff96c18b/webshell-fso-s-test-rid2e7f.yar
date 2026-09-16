rule Webshell_FSO_s_test_RID2E7F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file test.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:17:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$yazi = \"test\" . \"\\r\\n\";" 
      $s2 = "fwrite ($fp, \"$yazi\");" 
   condition: 
      all of them
}