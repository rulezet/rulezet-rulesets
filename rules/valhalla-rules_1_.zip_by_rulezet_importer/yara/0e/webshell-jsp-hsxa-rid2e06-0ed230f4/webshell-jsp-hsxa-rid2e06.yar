rule Webshell_jsp_hsxa_RID2E06 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file hsxa.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:56:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja" 
   condition: 
      all of them
}