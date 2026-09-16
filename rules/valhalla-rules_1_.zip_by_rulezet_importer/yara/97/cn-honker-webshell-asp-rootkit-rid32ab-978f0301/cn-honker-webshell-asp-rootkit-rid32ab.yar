rule CN_Honker_Webshell_ASP_rootkit_RID32AB : CHINA DEMO T1014 T1087_002 T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file rootkit.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:15:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1014, T1087_002, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "set ss=zsckm.get(\"Win32_ProcessSta\"&uyy&\"rtup\")" fullword ascii
      $s1 = "If jzgm=\"\"Then jzgm=\"cmd.exe /c net user\"" fullword ascii
   condition: 
      filesize < 80KB and all of them
}