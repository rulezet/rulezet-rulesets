rule Webshell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_php_RID3A0D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:30:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Welcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy" 
      $s1 = "Mode Shell v1.0</font></span>" 
      $s2 = "has been already loaded. PHP Emperor <xb5@hotmail." 
   condition: 
      1 of them
}