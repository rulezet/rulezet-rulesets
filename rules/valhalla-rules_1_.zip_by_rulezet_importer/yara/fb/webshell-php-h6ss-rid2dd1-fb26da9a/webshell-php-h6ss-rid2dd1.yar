rule Webshell_php_h6ss_RID2DD1 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file h6ss.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:48:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php eval(gzuncompress(base64_decode(\"" 
   condition: 
      all of them
}