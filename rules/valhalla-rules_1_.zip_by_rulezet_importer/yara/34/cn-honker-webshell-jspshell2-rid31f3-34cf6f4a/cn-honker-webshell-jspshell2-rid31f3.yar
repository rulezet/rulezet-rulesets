rule CN_Honker_Webshell_jspshell2_RID31F3 : CHINA DEMO T1007 T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jspshell2.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:44:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1007, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s10 = "if (cmd == null) cmd = \"cmd.exe /c set\";" fullword ascii
      $s11 = "if (program == null) program = \"cmd.exe /c net start > \"+SHELL_DIR+\"/Log.txt" ascii
   condition: 
      filesize < 424KB and all of them
}