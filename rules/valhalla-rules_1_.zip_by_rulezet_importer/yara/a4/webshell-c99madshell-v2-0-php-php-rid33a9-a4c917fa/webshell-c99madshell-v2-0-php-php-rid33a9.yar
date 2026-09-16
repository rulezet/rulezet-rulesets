rule Webshell_c99madshell_v2_0_php_php_RID33A9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file c99madshell_v2.0.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:57:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "eval(gzinflate(base64_decode('HJ3HkqNQEkU/ZzqCBd4t8V4YAQI2E3jvPV8/1Gw6orsVFLyXef" 
   condition: 
      all of them
}