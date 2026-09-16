rule CN_Honker_Webshell_cmfshell_RID31AA : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file cmfshell.cmf"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:32:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii
      $s2 = "<form action=\"<cfoutput>#CGI.SCRIPT_NAME#</cfoutput>\" method=\"post\">" fullword ascii
   condition: 
      filesize < 4KB and all of them
}