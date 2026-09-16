rule Webshell_PHP_Backdoor_Connect_pl_php_RID351D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file PHP Backdoor Connect.pl.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:59:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "LorD of IRAN HACKERS SABOTAGE" 
      $s1 = "LorD-C0d3r-NT" 
      $s2 = "echo --==Userinfo==-- ;" 
   condition: 
      1 of them
}