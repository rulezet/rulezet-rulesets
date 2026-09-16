rule Webshell_r577_php_php_SnIpEr_RID3199 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:29:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "911195a9b7c010f61b66439d9048f400"
      hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "'ru_text9' =>'???????? ????? ? ???????? ??? ? /bin/bash'," fullword
      $s1 = "$name='ec371748dc2da624b35a4f8f685dd122'" 
      $s2 = "rst.void.ru" 
   condition: 
      3 of them
}