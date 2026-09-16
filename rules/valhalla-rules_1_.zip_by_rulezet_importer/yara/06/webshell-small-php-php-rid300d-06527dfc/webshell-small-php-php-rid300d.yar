rule Webshell_small_php_php_RID300D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file small.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:23:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$pass='abcdef1234567890abcdef1234567890';" fullword
      $s2 = "eval(gzinflate(base64_decode('FJzHkqPatkU/550IGnjXxHvv6bzAe0iE5+svFVGtKqXMZq05x1" 
      $s4 = "@ini_set('error_log',NULL);" fullword
   condition: 
      2 of them
}