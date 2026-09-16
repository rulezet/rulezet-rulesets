rule Webshell_FSO_s_casus15_RID2F44 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file casus15.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:49:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "if((is_dir(\"$deldir/$file\")) AND ($file!=\".\") AND ($file!=\"..\"))" 
   condition: 
      all of them
}