rule CN_Honker_Webshell_Serv_U_servu_RID3344 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file servu.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:40:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "fputs ($conn_id, \"SITE EXEC \".$dir.\"cmd.exe /c \".$cmd.\"\\r\\n\");" fullword ascii
      $s1 = "function ftpcmd($ftpport,$user,$password,$dir,$cmd){" fullword ascii
   condition: 
      filesize < 41KB and all of them
}