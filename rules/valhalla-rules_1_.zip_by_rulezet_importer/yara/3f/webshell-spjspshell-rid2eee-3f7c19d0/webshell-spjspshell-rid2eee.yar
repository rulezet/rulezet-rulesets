rule Webshell_spjspshell_RID2EEE : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file spjspshell.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:35:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "Unix:/bin/sh -c tar vxf xxx.tar Windows:c:\\winnt\\system32\\cmd.exe /c type c:" 
   condition: 
      all of them
}