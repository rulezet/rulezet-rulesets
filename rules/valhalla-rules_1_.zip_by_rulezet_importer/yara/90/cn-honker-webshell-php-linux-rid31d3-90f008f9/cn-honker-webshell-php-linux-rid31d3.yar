rule CN_Honker_Webshell_PHP_linux_RID31D3 : CHINA DEMO FILE LINUX T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file linux.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:39:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, LINUX, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<form name=form1 action=exploit.php method=post>" fullword ascii
      $s1 = "<title>Changing CHMOD Permissions Exploit " fullword ascii
   condition: 
      uint16 ( 0 ) == 0x696c and filesize < 6KB and all of them
}