rule WebShell_PHP_Web_Kit_v3_RID2F7A : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      author = "Florian Roth"
      reference = "https://github.com/wordfence/grizzly"
      date = "2016-01-01 11:58:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $php = "<?php $" 
      $php2 = "@assert(base64_decode($_REQUEST[" 
      $s1 = "(str_replace(\"\\n\", '', '" 
      $s2 = "(strrev($" ascii
      $s3 = "de'.'code';" ascii
   condition: 
      ( ( uint32 ( 0 ) == 0x68703f3c and $php at 0 ) or $php2 ) and filesize > 8KB and filesize < 100KB and all of ( $s* )
}