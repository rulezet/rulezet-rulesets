rule CN_Honker_Webshell_phpwebbackup_RID3358 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file phpwebbackup.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:43:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php // Code By isosky www.nbst.org" fullword ascii
      $s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii
   condition: 
      uint16 ( 0 ) == 0x3f3c and filesize < 67KB and all of them
}