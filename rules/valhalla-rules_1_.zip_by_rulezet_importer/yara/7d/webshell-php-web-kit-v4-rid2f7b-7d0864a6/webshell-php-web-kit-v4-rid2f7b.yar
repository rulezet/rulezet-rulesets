rule WebShell_PHP_Web_Kit_v4_RID2F7B : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      author = "Florian Roth"
      reference = "https://github.com/wordfence/grizzly"
      date = "2016-01-01 11:59:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $php = "<?php $" 
      $s1 = "(StR_ReplAcE(\"\\n\",''," 
      $s2 = ";if(PHP_VERSION<'5'){" ascii
      $s3 = "=SuBstr_rePlACe(" ascii
   condition: 
      uint32 ( 0 ) == 0x68703f3c and $php at 0 and filesize > 8KB and filesize < 100KB and 2 of ( $s* )
}