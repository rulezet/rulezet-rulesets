rule WebShell_b374k_mini_shell_php_php_RID33C2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file b374k-mini-shell-php.php.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 15:01:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "@error_reporting(0);" fullword
      $s2 = "@eval(gzinflate(base64_decode($code)));" fullword
      $s3 = "@set_time_limit(0); " fullword
   condition: 
      all of them
}