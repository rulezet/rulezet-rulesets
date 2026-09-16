rule Webshell_PHP_shell_RID2E05 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:56:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "AR8iROET6mMnrqTpC6W1Kp/DsTgxNby9H1xhiswfwgoAtED0y6wEXTihoAtICkIX6L1+vTUYWuWz" 
      $s11 = "1HLp1qnlCyl5gko8rDlWHqf8/JoPKvGwEm9Q4nVKvEh0b0PKle3zeFiJNyjxOiVepMSpflJkPv5s" 
   condition: 
      all of them
}