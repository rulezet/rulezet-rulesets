rule Webshell_ASP_cmd_2_RID2DAE : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmd.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:42:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
   condition: 
      all of them
}