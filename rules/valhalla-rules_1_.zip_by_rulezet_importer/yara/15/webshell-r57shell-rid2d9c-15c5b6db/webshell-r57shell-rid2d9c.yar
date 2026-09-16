rule Webshell_r57shell_RID2D9C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file r57shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:39:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s11 = " $_POST['cmd']=\"echo \\\"Now script try connect to" 
   condition: 
      all of them
}