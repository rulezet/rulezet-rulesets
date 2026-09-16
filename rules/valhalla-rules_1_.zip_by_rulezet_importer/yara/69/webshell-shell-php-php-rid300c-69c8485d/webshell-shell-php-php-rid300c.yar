rule Webshell_shell_php_php_RID300C : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file shell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:23:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/* We have found the parent dir. We must be carefull if the parent " fullword
      $s2 = "$tmpfile = tempnam('/tmp', 'phpshell');" 
      $s3 = "if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {" fullword
   condition: 
      1 of them
}