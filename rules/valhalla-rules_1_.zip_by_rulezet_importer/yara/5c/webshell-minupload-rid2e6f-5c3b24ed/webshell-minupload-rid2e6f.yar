rule Webshell_minupload_RID2E6F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file minupload.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:14:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   " fullword
      $s9 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859" 
   condition: 
      all of them
}