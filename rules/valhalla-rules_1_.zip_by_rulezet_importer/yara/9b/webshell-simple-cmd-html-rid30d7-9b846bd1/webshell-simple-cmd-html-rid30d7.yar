rule Webshell_simple_cmd_html_RID30D7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file simple_cmd.html.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:57:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<title>G-Security Webshell</title>" fullword
      $s2 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
      $s3 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
      $s4 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
   condition: 
      all of them
}