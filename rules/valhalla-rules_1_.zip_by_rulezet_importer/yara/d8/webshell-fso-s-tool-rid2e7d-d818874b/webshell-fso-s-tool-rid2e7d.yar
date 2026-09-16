rule Webshell_FSO_s_tool_RID2E7D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file tool.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:16:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "\"\"%windir%\\\\calc.exe\"\")" 
   condition: 
      all of them
}