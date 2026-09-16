rule CN_Honker_Webshell_offlibrary_RID328C : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file offlibrary.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:09:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "';$i=$g->query(\"SELECT SUBSTRING_INDEX(CURRENT_USER, '@', 1) AS User, SUBSTRING" ascii
      $s12 = "if(jushRoot){var script=document.createElement('script');script.src=jushRoot+'ju" ascii
   condition: 
      filesize < 1005KB and all of them
}