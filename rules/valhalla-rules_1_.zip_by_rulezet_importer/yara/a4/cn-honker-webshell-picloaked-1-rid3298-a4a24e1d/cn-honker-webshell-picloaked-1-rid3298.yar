rule CN_Honker_Webshell_picloaked_1_RID3298 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file 1.gif"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:11:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php eval($_POST[" ascii
      $s1 = ";<%execute(request(" ascii
      $s3 = "GIF89a" fullword ascii
   condition: 
      filesize < 6KB and 2 of them
}