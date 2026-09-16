rule Webshell_jsp_123_RID2CE8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 123.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:09:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<font color=\"blue\">??????????????????:</font><input type=\"text\" size=\"7" 
      $s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"" 
      $s9 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">    " fullword
   condition: 
      all of them
}