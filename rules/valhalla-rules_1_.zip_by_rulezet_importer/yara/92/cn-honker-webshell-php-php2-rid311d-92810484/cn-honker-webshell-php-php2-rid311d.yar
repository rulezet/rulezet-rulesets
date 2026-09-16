rule CN_Honker_Webshell_PHP_php2_RID311D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php2.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:08:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii
      $s2 = "<?php // Black" fullword ascii
   condition: 
      filesize < 12KB and all of them
}