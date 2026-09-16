rule CN_Honker_Webshell_PHP_php4_RID311F : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php4.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:09:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "nc -l -vv -p port(" ascii
   condition: 
      uint16 ( 0 ) == 0x4850 and filesize < 1KB and all of them
}