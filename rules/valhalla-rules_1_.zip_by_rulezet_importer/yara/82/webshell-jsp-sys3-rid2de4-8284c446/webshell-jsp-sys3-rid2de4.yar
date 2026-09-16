rule Webshell_jsp_sys3_RID2DE4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file sys3.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:51:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">" fullword
      $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"" 
      $s9 = "<%@page contentType=\"text/html;charset=gb2312\"%>" fullword
   condition: 
      all of them
}