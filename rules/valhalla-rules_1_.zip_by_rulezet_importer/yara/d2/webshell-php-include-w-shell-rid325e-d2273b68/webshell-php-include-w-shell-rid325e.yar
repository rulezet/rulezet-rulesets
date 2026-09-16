rule WebShell_php_include_w_shell_RID325E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file php-include-w-shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:02:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s13 = "# dump variables (DEBUG SCRIPT) NEEDS MODIFINY FOR B64 STATUS!!" fullword
      $s17 = "\"phpshellapp\" => \"export TERM=xterm; bash -i\"," fullword
      $s19 = "else if($numhosts == 1) $strOutput .= \"On 1 host..\\n\";" fullword
   condition: 
      1 of them
}