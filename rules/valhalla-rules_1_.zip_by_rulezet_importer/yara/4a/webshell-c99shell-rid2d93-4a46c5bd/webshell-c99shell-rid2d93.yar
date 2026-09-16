rule Webshell_c99shell_RID2D93 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file c99shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:37:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<br />Input&nbsp;URL:&nbsp;&lt;input&nbsp;name=\\\"uploadurl\\\"&nbsp;type=\\\"text\\\"&" 
   condition: 
      all of them
}