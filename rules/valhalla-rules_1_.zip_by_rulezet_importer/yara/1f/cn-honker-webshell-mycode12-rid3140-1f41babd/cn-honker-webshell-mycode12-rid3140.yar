rule CN_Honker_Webshell_mycode12_RID3140 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file mycode12.cfm"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:14:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<cfexecute name=\"cmd.exe\"" fullword ascii
      $s2 = "<cfoutput>#cmd#</cfoutput>" fullword ascii
   condition: 
      filesize < 4KB and all of them
}