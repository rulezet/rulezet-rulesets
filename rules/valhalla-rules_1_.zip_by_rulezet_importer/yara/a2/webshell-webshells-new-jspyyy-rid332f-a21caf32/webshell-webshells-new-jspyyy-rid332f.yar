rule Webshell_webshells_new_jspyyy_RID332F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file jspyyy.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:37:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")" 
   condition: 
      all of them
}