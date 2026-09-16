rule Webshell_jsp_guige02_RID2EC5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file guige02.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:28:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#fff" 
      $s1 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private" 
   condition: 
      all of them
}