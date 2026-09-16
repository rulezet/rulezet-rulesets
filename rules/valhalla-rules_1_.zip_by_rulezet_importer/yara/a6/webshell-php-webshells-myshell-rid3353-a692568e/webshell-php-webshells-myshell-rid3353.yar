rule WebShell_php_webshells_myshell_RID3353 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file myshell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:43:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/outpu" 
      $s5 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o" 
      $s15 = "<title>$MyShellVersion - Access Denied</title>" fullword
      $s16 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTT" 
   condition: 
      1 of them
}