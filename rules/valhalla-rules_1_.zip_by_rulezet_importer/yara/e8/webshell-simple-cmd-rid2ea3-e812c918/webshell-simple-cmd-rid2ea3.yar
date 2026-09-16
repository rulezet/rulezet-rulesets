rule WebShell_simple_cmd_RID2EA3 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file simple_cmd.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:23:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
      $s2 = "<title>G-Security Webshell</title>" fullword
      $s4 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
      $s6 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
   condition: 
      1 of them
}