rule Webshell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_RID3866 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 18:19:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "die(\"\\nWelcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy\\n" 
      $s1 = "Mode Shell v1.0</font></span></a></font><font face=\"Webdings\" size=\"6\" color" 
   condition: 
      1 of them
}