rule Webshell_webshells_new_JJjsp3_RID328B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file JJjsp3.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:09:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S" 
   condition: 
      all of them
}