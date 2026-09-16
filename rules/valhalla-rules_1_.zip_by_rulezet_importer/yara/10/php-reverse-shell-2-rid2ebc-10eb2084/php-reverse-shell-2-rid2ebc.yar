rule php_reverse_shell_2_RID2EBC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file php-reverse-shell.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:27:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
      $s7 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii
   condition: 
      filesize < 10KB and all of them
}