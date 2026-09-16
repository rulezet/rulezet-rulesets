rule Webshell_FSO_s_phpinj_RID2F48 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phpinj.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:50:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';" 
   condition: 
      all of them
}