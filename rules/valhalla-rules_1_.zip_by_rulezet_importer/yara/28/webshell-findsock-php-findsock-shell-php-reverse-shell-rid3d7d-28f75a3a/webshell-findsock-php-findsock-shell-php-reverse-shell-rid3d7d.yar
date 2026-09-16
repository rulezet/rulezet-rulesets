rule WebShell__findsock_php_findsock_shell_php_reverse_shell_RID3D7D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - from files findsock.c, php-findsock-shell.php, php-reverse-shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 21:56:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a20f36035bbae8e342aab0418134e750b881d05"
      hash2 = "40dbdc0bdf5218af50741ba011c5286a723fa9bf"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "// me at pentestmonkey@pentestmonkey.net" fullword
   condition: 
      all of them
}