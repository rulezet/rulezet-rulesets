rule Webshell_PHPJackal_v1_5_RID2F6E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file PHPJackal v1.5.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:56:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "echo \"<center>${t}MySQL cilent:</td><td bgcolor=\\\"#333333\\\"></td></tr><form" 
      $s8 = "echo \"<center>${t}Wordlist generator:</td><td bgcolor=\\\"#333333\\\"></td></tr" 
   condition: 
      all of them
}