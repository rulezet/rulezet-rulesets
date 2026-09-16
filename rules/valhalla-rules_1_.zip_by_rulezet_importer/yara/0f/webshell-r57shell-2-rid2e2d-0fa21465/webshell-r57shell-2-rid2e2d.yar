rule Webshell_r57shell_2_RID2E2D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file r57shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:03:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo \"<br>\".ws(2).\"HDD Free : <b>\".view_size($free).\"</b> HDD Total : <b>\".view_" 
   condition: 
      all of them
}