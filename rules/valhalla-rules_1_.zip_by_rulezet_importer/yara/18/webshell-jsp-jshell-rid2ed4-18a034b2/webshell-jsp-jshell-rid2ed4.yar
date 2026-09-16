rule Webshell_jsp_jshell_RID2ED4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file jshell.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:31:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "kXpeW[\"" fullword
      $s4 = "[7b:g0W@W<" fullword
      $s5 = "b:gHr,g<" fullword
      $s8 = "RhV0W@W<" fullword
      $s9 = "S_MR(u7b" fullword
   condition: 
      all of them
}