rule Webshell_simple_backdoor_php_RID327B : DEMO T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file simple-backdoor.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:07:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$cmd = ($_REQUEST['cmd']);" fullword
      $s1 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" 
      $s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
   condition: 
      2 of them
}