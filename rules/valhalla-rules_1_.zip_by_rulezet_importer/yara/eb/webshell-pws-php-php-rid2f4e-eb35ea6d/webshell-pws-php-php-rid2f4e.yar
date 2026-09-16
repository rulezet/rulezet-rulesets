rule Webshell_pws_php_php_RID2F4E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file pws.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:51:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<div align=\"left\"><font size=\"1\">Input command :</font></div>" fullword
      $s1 = "<input type=\"text\" name=\"cmd\" size=\"30\" class=\"input\"><br>" fullword
      $s4 = "<input type=\"text\" name=\"dir\" size=\"30\" value=\"<? passthru(\"pwd\"); ?>" 
   condition: 
      2 of them
}