rule CN_Honker_Webshell_ASP_asp3_RID3116 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file asp3.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:07:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if shellpath=\"\" then shellpath = \"cmd.exe\"" fullword ascii
      $s2 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", Tru" ascii
   condition: 
      filesize < 444KB and all of them
}