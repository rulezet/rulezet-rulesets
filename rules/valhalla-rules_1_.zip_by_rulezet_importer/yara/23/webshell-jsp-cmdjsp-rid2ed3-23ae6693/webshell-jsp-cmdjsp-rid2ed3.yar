rule Webshell_jsp_cmdjsp_RID2ED3 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmdjsp.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:31:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
   condition: 
      all of them
}