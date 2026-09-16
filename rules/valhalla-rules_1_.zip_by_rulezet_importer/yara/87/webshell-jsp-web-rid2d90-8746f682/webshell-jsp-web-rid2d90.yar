rule Webshell_jsp_web_RID2D90 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file web.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:37:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request." 
   condition: 
      all of them
}