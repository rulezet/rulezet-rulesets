rule Webshell_backdoorfr_php_RID306A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file backdoorfr.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:38:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "www.victime.com/index.php?page=http://emplacement_de_la_backdoor.php , ou en tan" 
      $s2 = "print(\"<br>Provenance du mail : <input type=\\\"text\\\" name=\\\"provenanc" 
   condition: 
      1 of them
}