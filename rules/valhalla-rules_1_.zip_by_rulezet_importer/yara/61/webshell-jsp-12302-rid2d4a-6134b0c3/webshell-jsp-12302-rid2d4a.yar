rule Webshell_jsp_12302_RID2D4A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 12302.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:25:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "</font><%out.print(request.getRealPath(request.getServletPath())); %>" fullword
      $s1 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>" fullword
      $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"" 
   condition: 
      all of them
}