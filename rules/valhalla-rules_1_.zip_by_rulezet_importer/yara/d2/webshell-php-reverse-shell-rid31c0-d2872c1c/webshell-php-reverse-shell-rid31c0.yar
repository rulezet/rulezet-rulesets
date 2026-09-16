rule Webshell_php_reverse_shell_RID31C0 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file php-reverse-shell.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 13:35:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
      $s2 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii
      $s3 = "$input = fread($pipes[1], $chunk_size);" fullword ascii
   condition: 
      filesize < 15KB and all of them
}