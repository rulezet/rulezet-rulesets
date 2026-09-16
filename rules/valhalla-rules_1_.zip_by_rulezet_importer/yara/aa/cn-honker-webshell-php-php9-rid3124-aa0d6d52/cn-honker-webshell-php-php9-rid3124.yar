rule CN_Honker_Webshell_PHP_php9_RID3124 : CHINA DEMO T1087_002 T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php9.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:09:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1087_002, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Str[17] = \"select shell('c:\\windows\\system32\\cmd.exe /c net user b4che10r ab" ascii
   condition: 
      filesize < 1087KB and all of them
}