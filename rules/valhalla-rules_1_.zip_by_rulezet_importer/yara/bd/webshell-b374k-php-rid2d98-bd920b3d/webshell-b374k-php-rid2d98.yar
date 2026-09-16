rule WebShell_b374k_php_RID2D98 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file b374k.php.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:38:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "// encrypt your password to md5 here http://kerinci.net/?x=decode" fullword
      $s6 = "// password (default is: b374k)" 
      $s8 = "//******************************************************************************" 
      $s9 = "// b374k 2.2" fullword
      $s10 = "eval(\"?>\".gzinflate(base64_decode(" 
   condition: 
      3 of them
}