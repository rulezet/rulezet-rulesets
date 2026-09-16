rule Webshell_Test_php_php_RID2F94 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Test.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:03:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$yazi = \"test\" . \"\\r\\n\";" fullword
      $s2 = "fwrite ($fp, \"$yazi\");" fullword
      $s3 = "$entry_line=\"HACKed by EntriKa\";" fullword
   condition: 
      1 of them
}