rule Webshell_Antichat_Shell_v1_3_php_RID3368 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Antichat Shell v1.3.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:46:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Antichat" 
      $s1 = "Can't open file, permission denide" 
      $s2 = "$ra44" 
   condition: 
      2 of them
}