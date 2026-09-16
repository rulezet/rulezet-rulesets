rule Webshell_jsp_action_RID2ED0 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file action.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:30:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword
      $s6 = "<%@ page contentType=\"text/html;charset=gb2312\"%>" fullword
   condition: 
      all of them
}