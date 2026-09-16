rule Webshell_webadmin_RID2DED : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file webadmin.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:52:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<input name=\\\"editfilename\\\" type=\\\"text\\\" class=\\\"style1\\\" value='\".$this->inpu" 
   condition: 
      all of them
}