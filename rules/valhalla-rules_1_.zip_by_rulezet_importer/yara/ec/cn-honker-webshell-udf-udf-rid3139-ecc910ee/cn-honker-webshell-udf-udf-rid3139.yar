rule CN_Honker_Webshell_udf_udf_RID3139 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file udf.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:13:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<?php // Source  My : Meiam  " fullword ascii
      $s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii
   condition: 
      filesize < 430KB and all of them
}