rule CN_Honker_Webshell_ASP_hy2006a_RID31A9 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file hy2006a.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:32:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s15 = "Const myCmdDotExeFile = \"command.com\"" fullword ascii
      $s16 = "If LCase(appName) = \"cmd.exe\" And appArgs <> \"\" Then" fullword ascii
   condition: 
      filesize < 406KB and all of them
}