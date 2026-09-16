rule CN_Honker_Webshell_cfmShell_RID318A : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file cfmShell.cfm"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:26:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii
      $s4 = "<cfif FileExists(\"#GetTempDirectory()#foobar.txt\") is \"Yes\">" fullword ascii
   condition: 
      filesize < 4KB and all of them
}