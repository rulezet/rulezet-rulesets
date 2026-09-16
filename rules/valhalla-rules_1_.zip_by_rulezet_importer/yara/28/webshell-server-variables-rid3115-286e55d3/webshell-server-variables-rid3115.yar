rule Webshell_Server_Variables_RID3115 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Server Variables.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:07:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "<% For Each Vars In Request.ServerVariables %>" fullword
      $s9 = "Variable Name</B></font></p>" fullword
   condition: 
      all of them
}