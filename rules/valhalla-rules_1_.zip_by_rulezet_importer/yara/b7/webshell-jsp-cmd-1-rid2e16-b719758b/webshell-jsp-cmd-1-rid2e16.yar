rule Webshell_jsp_cmd_1_RID2E16 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmd.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:59:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword
   condition: 
      all of them
}