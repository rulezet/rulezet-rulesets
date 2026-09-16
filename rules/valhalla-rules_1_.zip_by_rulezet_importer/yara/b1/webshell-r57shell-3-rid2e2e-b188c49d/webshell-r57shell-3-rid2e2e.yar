rule Webshell_r57shell_3_RID2E2E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file r57shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:03:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<b>\".$_POST['cmd']" 
   condition: 
      all of them
}