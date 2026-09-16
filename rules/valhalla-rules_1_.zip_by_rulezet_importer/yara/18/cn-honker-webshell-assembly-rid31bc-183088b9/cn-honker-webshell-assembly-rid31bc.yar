rule CN_Honker_Webshell_assembly_RID31BC : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file assembly.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:35:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "response.write oScriptlhn.exec(\"cmd.exe /c\" & request(\"c\")).stdout.readall" fullword ascii
   condition: 
      filesize < 1KB and all of them
}